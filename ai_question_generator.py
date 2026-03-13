"""
AI Question Generator Engine
Uses Google GenAI SDK directly + pypdf for PDF text extraction.

ROOT CAUSE FIX:
  The old implementation used GoogleGenerativeAIEmbeddings (langchain_google_genai)
  alongside google.genai Client. Both try to initialize SSL/gRPC transports,
  causing "maximum recursion depth exceeded".

SOLUTION:
  - Removed FAISS vector store and LangChain embeddings entirely.
  - PDF text is extracted with pypdf (already in requirements.txt).
  - Context is passed straight to Gemini — no embedding pipeline.
  - Eliminates the SSL recursion and speeds up generation significantly.
"""

import os
import json
import re
from typing import List, Dict, Optional

from pydantic import BaseModel, Field, validator
from pypdf import PdfReader
from google import genai
from google.genai import types


# ========================
# LATEX SANITIZER
# ========================

def sanitize_latex(text: str) -> str:
    """Sanitize and normalize LaTeX field values."""
    if not text:
        return text
    stripped = text.strip()
    if stripped.startswith('$$') and stripped.endswith('$$'):
        inner = stripped[2:-2].strip()
    elif stripped.startswith('$') and stripped.endswith('$'):
        inner = stripped[1:-1].strip()
    else:
        inner = stripped
    inner = re.sub(r'^\\large\s*', '', inner).strip()
    def fix_text_block(m):
        content = m.group(1)
        content = content.replace('$$', '').replace('$', '')
        return r'\text{' + content + '}'
    inner = re.sub(r'\\text\{([^}]*)\}', fix_text_block, inner)
    return r'$\large ' + inner + r' $'


# ========================
# PYDANTIC MODELS
# ========================

class QuestionModel(BaseModel):
    """Strict validation model for generated questions"""
    exam_id: int
    question_text: str
    option_a: str = ""
    option_b: str = ""
    option_c: str = ""
    option_d: str = ""
    correct_answer: str
    question_type: str = Field(default="MCQ")
    positive_marks: float = Field(default=4.0)
    negative_marks: float = Field(default=1.0)
    tolerance: float = Field(default=0.0)

    @validator('question_text', pre=True, always=True)
    def sanitize_question_text(cls, v):
        return sanitize_latex(str(v)) if v else v

    @validator('option_a', 'option_b', 'option_c', 'option_d', pre=True, always=True)
    def sanitize_options(cls, v):
        if v and str(v).strip() not in ('', 'nan', 'None'):
            return sanitize_latex(str(v))
        return ""

    @validator('question_type')
    def validate_question_type(cls, v):
        if v not in ['MCQ', 'MSQ', 'NUMERIC']:
            raise ValueError('question_type must be MCQ, MSQ, or NUMERIC')
        return v

    @validator('option_a', 'option_b', 'option_c', 'option_d')
    def validate_options_numeric(cls, v, values):
        if values.get('question_type') == 'NUMERIC':
            return ""
        return v

    class Config:
        extra = 'forbid'


# ========================
# PROMPT TEMPLATES
# ========================

_LATEX_RULES = r"""
STRICT LATEX FORMATTING RULES:
1.  Every question_text and option MUST use: $\large \text{Your text here} $
2.  For inline math: $\large \text{Mass } m \text{ with } \mu $
3.  For fractions: $\large \frac{a}{b} $
4.  For vectors: $\large \vec{F} = m\vec{a} $
5.  NEVER nest $$ or $ inside \text{}.
6.  NEVER use $$...$$ — only single $ wrappers.
7.  NEVER use markdown backticks in the JSON.
8.  Use SINGLE backslash: \frac, \text, \vec, \mu, etc.
9.  Return ONLY a raw JSON array — no extra text before or after.
"""

_OUTPUT_RULES = r"""
- NUMERIC: options A,B,C,D MUST be empty strings ""
- MSQ: correct_answer can be "A,C" or "A,B,D"
- MCQ: correct_answer must be single letter
"""


def _config_block(config: Dict) -> str:
    return (
        f"CONFIGURATION:\n"
        f"- Exam ID: {config['exam_id']}\n"
        f"- Difficulty: {config['difficulty']}\n"
        f"- Counts: MCQ={config.get('mcq_count', 0)}, "
        f"MSQ={config.get('msq_count', 0)}, "
        f"NUMERIC={config.get('numeric_count', 0)}\n"
        f"- MCQ marks: +{config.get('mcq_plus', 4)}/-{config.get('mcq_minus', 1)}\n"
        f"- MSQ marks: +{config.get('msq_plus', 4)}/-{config.get('msq_minus', 2)}\n"
        f"- NUMERIC marks: +{config.get('numeric_plus', 3)}, "
        f"tolerance={config.get('numeric_tolerance', 0.01)}\n"
        f"- Custom Instructions: {config.get('custom_instructions', 'None')}"
    )


def _count_line(config: Dict) -> str:
    return (
        f"Generate exactly {config.get('mcq_count', 0)} MCQ, "
        f"{config.get('msq_count', 0)} MSQ, and "
        f"{config.get('numeric_count', 0)} NUMERIC questions."
    )


def _schema_example(exam_id: int) -> str:
    return (
        '[{\n'
        f'  "exam_id": {exam_id},\n'
        '  "question_text": "$\\\\large \\\\text{Your question here} $",\n'
        '  "option_a": "$\\\\large \\\\text{Option A} $",\n'
        '  "option_b": "$\\\\large \\\\text{Option B} $",\n'
        '  "option_c": "$\\\\large \\\\text{Option C} $",\n'
        '  "option_d": "$\\\\large \\\\text{Option D} $",\n'
        '  "correct_answer": "A",\n'
        '  "question_type": "MCQ",\n'
        '  "positive_marks": 4.0,\n'
        '  "negative_marks": 1.0,\n'
        '  "tolerance": 0.0\n'
        '}]'
    )


# ========================
# CORE ENGINE
# ========================

_MAX_CONTEXT_CHARS = 12000  # ~3k tokens — fast and sufficient


class AIQuestionGenerator:
    """
    Fast, stable question generator.
    - pypdf for direct PDF text extraction (no FAISS, no LangChain embeddings).
    - Single google.genai Client — no SSL recursion possible.
    - Clean error handling — never crashes the caller.
    """

    def __init__(self, api_key: str = None):
        self.api_key = api_key or os.environ.get('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")
        model_raw = os.environ.get('GEMINI_MODEL_NAME', 'gemini-1.5-flash')
        self.model_name = model_raw.replace('models/', '')
        self.client = genai.Client(api_key=self.api_key)
        print(f"AI Question Generator ready — model: {self.model_name}")

    # ------------------------------------------------------------------
    # PDF text extraction
    # ------------------------------------------------------------------

    def extract_pdf_text(self, pdf_path: str) -> str:
        """Extract text from PDF using pypdf — fast, no embeddings needed."""
        try:
            reader = PdfReader(pdf_path)
            parts = []
            total = 0
            for page in reader.pages:
                text = page.extract_text() or ""
                parts.append(text)
                total += len(text)
                if total >= _MAX_CONTEXT_CHARS:
                    break
            return "\n\n".join(parts)[:_MAX_CONTEXT_CHARS]
        except Exception as e:
            raise Exception(f"PDF extraction failed: {str(e)}")

    # ------------------------------------------------------------------
    # Gemini API call
    # ------------------------------------------------------------------

    def generate_text(self, prompt: str) -> str:
        """Single Gemini call with JSON mode. No retries — clean error on failure."""
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json'
                ),
            )
            return response.text
        except Exception as e:
            raise Exception(f"Gemini API error: {str(e)}")

    # ------------------------------------------------------------------
    # Generation modes
    # ------------------------------------------------------------------

    def extract_from_pdf(self, pdf_path: str, config: Dict) -> List[Dict]:
        """Card A: Extract existing questions from PDF."""
        context = self.extract_pdf_text(pdf_path)
        prompt = (
            "You are a Professional Question Paper Designer for JEE/NEET level exams.\n"
            "Extract questions from the provided PDF content.\n\n"
            f"PDF CONTENT:\n{context}\n\n"
            f"{_config_block(config)}\n\n"
            f"Return ONLY a valid JSON array. Example schema:\n{_schema_example(config['exam_id'])}\n\n"
            f"{_LATEX_RULES}\n{_OUTPUT_RULES}\n{_count_line(config)}"
        )
        return self._parse_and_validate(self.generate_text(prompt), config)

    def mine_concepts(self, pdf_path: str, config: Dict) -> List[Dict]:
        """Card B: Generate new questions from theory/concepts."""
        context = self.extract_pdf_text(pdf_path)
        prompt = (
            "You are a Professional Question Paper Designer for JEE/NEET level exams.\n"
            "Generate NEW, HIGH-QUALITY questions from the theory content below.\n\n"
            f"THEORY CONTENT:\n{context}\n\n"
            f"{_config_block(config)}\n\n"
            f"Return ONLY a valid JSON array. Example schema:\n{_schema_example(config['exam_id'])}\n\n"
            f"{_LATEX_RULES}\n{_OUTPUT_RULES}\n"
            f"Match the '{config['difficulty']}' difficulty level.\n"
            f"{_count_line(config)}"
        )
        return self._parse_and_validate(self.generate_text(prompt), config)

    def generate_from_topic(self, topic: str, config: Dict) -> List[Dict]:
        """Card C: Pure generation from topic name — no PDF needed."""
        prompt = (
            "You are a Professional Question Paper Designer for JEE/NEET level exams.\n"
            f"Generate HIGH-QUALITY questions on the topic: {topic}\n\n"
            f"{_config_block(config)}\n\n"
            f"Return ONLY a valid JSON array. Example schema:\n{_schema_example(config['exam_id'])}\n\n"
            f"{_LATEX_RULES}\n{_OUTPUT_RULES}\n"
            f"Match the '{config['difficulty']}' difficulty level.\n"
            f"{_count_line(config)}"
        )
        return self._parse_and_validate(self.generate_text(prompt), config)

    # ------------------------------------------------------------------
    # JSON parsing + Pydantic validation
    # ------------------------------------------------------------------

    def _fix_invalid_escapes(self, raw: str) -> str:
        """
        Double-escape bare LaTeX backslashes inside JSON strings so json.loads works.
        Only \\\\  and \\\"  are valid JSON escape sequences.
        All other backslash sequences are LaTeX — double them.
        """
        result = []
        in_string = False
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == '"' and (i == 0 or raw[i - 1] != '\\'):
                in_string = not in_string
                result.append(ch)
                i += 1
            elif ch == '\\' and in_string:
                next_ch = raw[i + 1] if i + 1 < len(raw) else ''
                if next_ch in ('\\', '"'):
                    result.append(ch)
                    result.append(next_ch)
                    i += 2
                else:
                    result.append('\\\\')
                    i += 1
            else:
                result.append(ch)
                i += 1
        return ''.join(result)

    def _parse_and_validate(self, llm_output: str, config: Dict) -> List[Dict]:
        """Parse LLM JSON output and validate with Pydantic."""
        try:
            cleaned = llm_output.strip()
            cleaned = re.sub(r'^```json\s*', '', cleaned)
            cleaned = re.sub(r'^```\s*', '', cleaned)
            cleaned = re.sub(r'\s*```$', '', cleaned)
            cleaned = cleaned.strip()
            cleaned = self._fix_invalid_escapes(cleaned)

            questions = json.loads(cleaned)
            if not isinstance(questions, list):
                raise ValueError("Output must be a JSON array")

            validated = []
            for q in questions:
                try:
                    validated.append(QuestionModel(**q).dict())
                except Exception as e:
                    print(f"Skipping invalid question: {e}")

            if not validated:
                raise ValueError("No valid questions were generated")
            return validated

        except json.JSONDecodeError as e:
            raise Exception(
                f"Invalid JSON from AI: {str(e)}\nOutput preview: {llm_output[:500]}"
            )
        except Exception as e:
            raise Exception(f"Validation failed: {str(e)}")


# ========================
# PUBLIC ENTRY POINT
# ========================

def generate_questions(
    mode: str,
    config: Dict,
    pdf_path: Optional[str] = None,
    topic: Optional[str] = None,
) -> List[Dict]:
    """
    Generate questions via AI.
    mode: 'extract' | 'mine' | 'pure'
    Raises a clean Exception on failure — never crashes the caller.
    """
    generator = AIQuestionGenerator()

    if mode == 'extract':
        if not pdf_path:
            raise ValueError("PDF path required for extraction mode")
        return generator.extract_from_pdf(pdf_path, config)
    elif mode == 'mine':
        if not pdf_path:
            raise ValueError("PDF path required for concept mining mode")
        return generator.mine_concepts(pdf_path, config)
    elif mode == 'pure':
        if not topic:
            raise ValueError("Topic required for pure generation mode")
        return generator.generate_from_topic(topic, config)
    else:
        raise ValueError(f"Invalid mode: {mode}")