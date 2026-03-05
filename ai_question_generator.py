"""
AI Question Generator Engine - LATEST GEMINI API
Uses Google GenAI SDK (Latest) + LangChain for RAG
"""

import os
import json
import gc
from typing import List, Dict, Optional
from pydantic import BaseModel, Field, validator
import re

# Latest Google GenAI import
from google import genai
from google.genai import types

# LangChain imports (only for RAG and text processing)
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.vectorstores import FAISS
from langchain_community.document_loaders import PyPDFLoader
from langchain_google_genai import GoogleGenerativeAIEmbeddings


# ========================
# LATEX SANITIZER
# ========================

def sanitize_latex(text: str) -> str:
    """
    Sanitize LaTeX in a field value.

    Rules enforced:
    1. Strip outer $...$ or $$...$$ if present, then re-wrap correctly.
    2. Remove any $$ or $ nested inside \text{} blocks.
    3. Convert \text{ $$ expr $$ } → pull the math out: \text{prefix} expr \text{suffix}
    4. Ensure final output is:  $\large CONTENT $
       where CONTENT is plain LaTeX (text in \text{}, math inline).
    5. Never double-escape backslashes — the string at this point is
       already a normal Python string (JSON has been decoded).
    """
    if not text:
        return text

    # ── Step 1: strip outer dollar wrappers ──────────────────────────────
    # handles $$...$$ and $...$
    stripped = text.strip()
    if stripped.startswith('$$') and stripped.endswith('$$'):
        inner = stripped[2:-2].strip()
    elif stripped.startswith('$') and stripped.endswith('$'):
        inner = stripped[1:-1].strip()
    else:
        inner = stripped

    # ── Step 2: remove \large at the start if present (we'll add it back) ─
    inner = re.sub(r'^\\large\s*', '', inner).strip()

    # ── Step 3: fix $$ or $ nested inside \text{...} ─────────────────────
    # Pattern: \text{ ... $$ expr $$ ... }  →  \text{ ... } expr \text{ ... }
    # We do a simple removal: strip $ and $$ that appear inside \text{} args.
    def fix_text_block(m):
        content = m.group(1)
        # remove any $$ or $ inside \text{} content
        content = content.replace('$$', '').replace('$', '')
        return r'\text{' + content + '}'

    inner = re.sub(r'\\text\{([^}]*)\}', fix_text_block, inner)

    # ── Step 4: re-wrap with $\large ... $ ───────────────────────────────
    result = r'$\large ' + inner + r' $'
    return result


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

    # ── Pre-validators: sanitize LaTeX before any other validation ────────
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

# Shared LaTeX rules block (used in all three prompts)
_LATEX_RULES = r"""
STRICT LATEX FORMATTING RULES — READ CAREFULLY:
1.  Every question_text and option MUST use this exact wrapper:
      $\large \text{Your plain text here} $
2.  For inline math inside a sentence, break out of \text{} like this:
      $\large \text{A block of mass } m \text{ on surface with } \mu $
3.  For fractions:
      $\large \frac{a}{b} $
4.  For vectors:
      $\large \vec{F} = m\vec{a} $
5.  For chemistry reactions:
      $\large \text{2H}_2 + \text{O}_2 \rightarrow \text{2H}_2\text{O} $
6.  NEVER nest $$ or $ inside \text{}.  WRONG: \text{use $\frac{a}{b}$}
7.  NEVER use $$...$$ anywhere — only single $ wrappers.
8.  NEVER use markdown backticks (```) anywhere in the JSON.
9.  Use SINGLE backslash for all LaTeX commands: \frac, \text, \vec, \mu, etc.
10. Return ONLY a raw JSON array — no extra text before or after.
"""

EXTRACTION_PROMPT = """You are a Professional Question Paper Designer for JEE/NEET level exams.

Extract questions from the provided PDF content and format them according to the strict rules below.

PDF CONTENT:
{context}

CONFIGURATION:
- Exam ID: {exam_id}
- Difficulty: {difficulty}
- Question Counts: MCQ={mcq_count}, MSQ={msq_count}, NUMERIC={numeric_count}
- MCQ: +{mcq_plus}/-{mcq_minus} marks
- MSQ: +{msq_plus}/-{msq_minus} marks  
- NUMERIC: +{numeric_plus} marks, tolerance={numeric_tolerance}

CUSTOM INSTRUCTIONS:
{custom_instructions}

OUTPUT REQUIREMENTS:
Return ONLY a valid JSON array. Each object must follow this exact schema:

{{
  "exam_id": {exam_id},
  "question_text": "$\\large \\text{{Your question here}} $",
  "option_a": "$\\large \\text{{Option A}} $",
  "option_b": "$\\large \\text{{Option B}} $",
  "option_c": "$\\large \\text{{Option C}} $",
  "option_d": "$\\large \\text{{Option D}} $",
  "correct_answer": "A",
  "question_type": "MCQ",
  "positive_marks": 4.0,
  "negative_marks": 1.0,
  "tolerance": 0.0
}}

{latex_rules}

- NUMERIC: options A,B,C,D MUST be empty strings ""
- MSQ: correct_answer can be "A,C" or "A,B,D"
- MCQ: correct_answer must be single letter

Generate exactly {mcq_count} MCQ, {msq_count} MSQ, and {numeric_count} NUMERIC questions.
"""

CONCEPT_MINING_PROMPT = """You are a Professional Question Paper Designer for JEE/NEET level exams.

Read the theory/textbook content and generate NEW, HIGH-QUALITY questions based on the concepts.

THEORY CONTENT:
{context}

CONFIGURATION:
- Exam ID: {exam_id}
- Difficulty: {difficulty}
- Question Counts: MCQ={mcq_count}, MSQ={msq_count}, NUMERIC={numeric_count}
- MCQ: +{mcq_plus}/-{mcq_minus} marks
- MSQ: +{msq_plus}/-{msq_minus} marks  
- NUMERIC: +{numeric_plus} marks, tolerance={numeric_tolerance}

CUSTOM INSTRUCTIONS:
{custom_instructions}

OUTPUT REQUIREMENTS:
Return ONLY a valid JSON array. Each object must follow this exact schema:

{{
  "exam_id": {exam_id},
  "question_text": "$\\large \\text{{Your question here}} $",
  "option_a": "$\\large \\text{{Option A}} $",
  "option_b": "$\\large \\text{{Option B}} $",
  "option_c": "$\\large \\text{{Option C}} $",
  "option_d": "$\\large \\text{{Option D}} $",
  "correct_answer": "A",
  "question_type": "MCQ",
  "positive_marks": 4.0,
  "negative_marks": 1.0,
  "tolerance": 0.0
}}

{latex_rules}

- NUMERIC: options A,B,C,D MUST be empty strings ""
- MSQ: correct_answer can be "A,C" or "A,B,D"
- MCQ: correct_answer must be single letter
- Quality: Questions must match the '{difficulty}' difficulty level
- Conceptual: Base questions on actual concepts from the content

Generate exactly {mcq_count} MCQ, {msq_count} MSQ, and {numeric_count} NUMERIC questions.
"""

PURE_GENERATION_PROMPT = """You are a Professional Question Paper Designer for JEE/NEET level exams.

Generate HIGH-QUALITY questions on the given topic without any reference material.

TOPIC: {topic}

CONFIGURATION:
- Exam ID: {exam_id}
- Difficulty: {difficulty}
- Question Counts: MCQ={mcq_count}, MSQ={msq_count}, NUMERIC={numeric_count}
- MCQ: +{mcq_plus}/-{mcq_minus} marks
- MSQ: +{msq_plus}/-{msq_minus} marks  
- NUMERIC: +{numeric_plus} marks, tolerance={numeric_tolerance}

CUSTOM INSTRUCTIONS:
{custom_instructions}

OUTPUT REQUIREMENTS:
Return ONLY a valid JSON array. Each object must follow this exact schema:

{{
  "exam_id": {exam_id},
  "question_text": "$\\large \\text{{Your question here}} $",
  "option_a": "$\\large \\text{{Option A}} $",
  "option_b": "$\\large \\text{{Option B}} $",
  "option_c": "$\\large \\text{{Option C}} $",
  "option_d": "$\\large \\text{{Option D}} $",
  "correct_answer": "A",
  "question_type": "MCQ",
  "positive_marks": 4.0,
  "negative_marks": 1.0,
  "tolerance": 0.0
}}

{latex_rules}

- NUMERIC: options A,B,C,D MUST be empty strings ""
- MSQ: correct_answer can be "A,C" or "A,B,D"
- MCQ: correct_answer must be single letter
- Quality: Questions must match the '{difficulty}' difficulty level
- Variety: Cover different aspects of the topic

Generate exactly {mcq_count} MCQ, {msq_count} MSQ, and {numeric_count} NUMERIC questions.
"""


# ========================
# CORE ENGINE CLASS
# ========================

class AIQuestionGenerator:
    """Main engine for AI-powered question generation"""

    def __init__(self, api_key: str = None):
        """Initialize with Gemini API key"""
        self.api_key = api_key or os.environ.get('GEMINI_API_KEY')
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY not found in environment")

        model_name_raw = os.environ.get('GEMINI_MODEL_NAME', 'gemini-1.5-flash')
        if not model_name_raw.startswith('models/'):
            self.model_name = f'models/{model_name_raw}'
        else:
            self.model_name = model_name_raw

        # ✅ LATEST Gemini API initialization
        self.client = genai.Client(api_key=self.api_key)

        print(f"✅ Initialized Gemini with model: {self.model_name}")

        # Initialize embeddings for RAG
        self.embeddings = GoogleGenerativeAIEmbeddings(
            model="gemini-embedding-001",
            google_api_key=self.api_key
        )

        # Text splitter for chunking
        self.text_splitter = RecursiveCharacterTextSplitter(
            chunk_size=1500,
            chunk_overlap=200,
            length_function=len
        )

    def generate_text(self, prompt: str) -> str:
        """
        Generate text using Gemini Native JSON Mode.
        response_mime_type='application/json' forces the model to return
        valid JSON directly — no markdown fences, no preamble.
        """
        try:
            response = self.client.models.generate_content(
                model=self.model_name,
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type='application/json'
                )
            )
            return response.text
        except Exception as e:
            raise Exception(f"Gemini API error: {str(e)}")

    def load_pdf(self, pdf_path: str) -> List[str]:
        """Load and split PDF into chunks"""
        try:
            loader = PyPDFLoader(pdf_path)
            documents = loader.load()
            chunks = self.text_splitter.split_documents(documents)
            return chunks
        except Exception as e:
            raise Exception(f"PDF loading failed: {str(e)}")

    def create_vectorstore(self, chunks: List) -> FAISS:
        """Create temporary FAISS vector store"""
        try:
            vectorstore = FAISS.from_documents(chunks, self.embeddings)
            return vectorstore
        except Exception as e:
            raise Exception(f"Vector store creation failed: {str(e)}")

    def extract_from_pdf(self, pdf_path: str, config: Dict) -> List[Dict]:
        """Card A: Extract existing questions from PDF"""
        try:
            chunks = self.load_pdf(pdf_path)
            vectorstore = self.create_vectorstore(chunks)

            retriever = vectorstore.as_retriever(search_kwargs={"k": 10})
            relevant_docs = retriever.invoke("Extract all questions")
            context = "\n\n".join([doc.page_content for doc in relevant_docs])

            prompt = EXTRACTION_PROMPT.format(
                context=context,
                exam_id=config['exam_id'],
                difficulty=config['difficulty'],
                mcq_count=config.get('mcq_count', 0),
                msq_count=config.get('msq_count', 0),
                numeric_count=config.get('numeric_count', 0),
                mcq_plus=config.get('mcq_plus', 4),
                mcq_minus=config.get('mcq_minus', 1),
                msq_plus=config.get('msq_plus', 4),
                msq_minus=config.get('msq_minus', 2),
                numeric_plus=config.get('numeric_plus', 3),
                numeric_tolerance=config.get('numeric_tolerance', 0.01),
                custom_instructions=config.get('custom_instructions', 'None'),
                latex_rules=_LATEX_RULES
            )

            result = self.generate_text(prompt)

            del vectorstore
            gc.collect()

            return self._parse_and_validate(result, config)

        except Exception as e:
            raise Exception(f"Extraction failed: {str(e)}")

    def mine_concepts(self, pdf_path: str, config: Dict) -> List[Dict]:
        """Card B: Generate new questions from theory/concepts"""
        try:
            chunks = self.load_pdf(pdf_path)
            vectorstore = self.create_vectorstore(chunks)

            retriever = vectorstore.as_retriever(search_kwargs={"k": 15})
            relevant_docs = retriever.invoke("Get all concepts and theory")
            context = "\n\n".join([doc.page_content for doc in relevant_docs])

            prompt = CONCEPT_MINING_PROMPT.format(
                context=context,
                exam_id=config['exam_id'],
                difficulty=config['difficulty'],
                mcq_count=config.get('mcq_count', 0),
                msq_count=config.get('msq_count', 0),
                numeric_count=config.get('numeric_count', 0),
                mcq_plus=config.get('mcq_plus', 4),
                mcq_minus=config.get('mcq_minus', 1),
                msq_plus=config.get('msq_plus', 4),
                msq_minus=config.get('msq_minus', 2),
                numeric_plus=config.get('numeric_plus', 3),
                numeric_tolerance=config.get('numeric_tolerance', 0.01),
                custom_instructions=config.get('custom_instructions', 'None'),
                latex_rules=_LATEX_RULES
            )

            result = self.generate_text(prompt)

            del vectorstore
            gc.collect()

            return self._parse_and_validate(result, config)

        except Exception as e:
            raise Exception(f"Concept mining failed: {str(e)}")

    def generate_from_topic(self, topic: str, config: Dict) -> List[Dict]:
        """Card C: Pure generation from topic name"""
        try:
            prompt = PURE_GENERATION_PROMPT.format(
                topic=topic,
                exam_id=config['exam_id'],
                difficulty=config['difficulty'],
                mcq_count=config.get('mcq_count', 0),
                msq_count=config.get('msq_count', 0),
                numeric_count=config.get('numeric_count', 0),
                mcq_plus=config.get('mcq_plus', 4),
                mcq_minus=config.get('mcq_minus', 1),
                msq_plus=config.get('msq_plus', 4),
                msq_minus=config.get('msq_minus', 2),
                numeric_plus=config.get('numeric_plus', 3),
                numeric_tolerance=config.get('numeric_tolerance', 0.01),
                custom_instructions=config.get('custom_instructions', 'None'),
                latex_rules=_LATEX_RULES
            )

            result = self.generate_text(prompt)

            return self._parse_and_validate(result, config)

        except Exception as e:
            raise Exception(f"Pure generation failed: {str(e)}")

    def _fix_invalid_escapes(self, raw: str) -> str:
        """
        Fix single-backslash LaTeX commands that are invalid JSON escape sequences.

        BUG FIX: Old VALID set included b,f,n,r,t which caused:
          \\text  -> \\t treated as tab, leaving "ext"
          \\frac  -> \\f treated as form-feed, leaving "rac"
          \\newline -> \\n treated as newline, leaving "ewline"
          \\rightarrow -> \\r treated as CR, leaving "ightarrow"

        Fix: Only keep \\\\ and \\" as pre-valid.
        All other backslash sequences are LaTeX commands needing doubling.
        """
        VALID = {'\\', '"'}

        result = []
        in_string = False
        i = 0
        while i < len(raw):
            ch = raw[i]
            if ch == '"' and (i == 0 or raw[i-1] != '\\'):
                in_string = not in_string
                result.append(ch)
                i += 1
            elif ch == '\\' and in_string:
                next_ch = raw[i+1] if i+1 < len(raw) else ''
                if next_ch == '\\' or next_ch == '"':
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
        """
        Parse LLM JSON output and validate with Pydantic.

        - Strips markdown fences (safety net).
        - Fixes single-backslash LaTeX that breaks json.loads().
        - NO blanket replace("\\","\\\\") — that double-escapes already valid escapes.
        - Pydantic pre-validators handle LaTeX sanitization per field.
        """
        try:
            cleaned = llm_output.strip()

            # Safety net: strip markdown fences if model ignored JSON mode
            cleaned = re.sub(r'^```json\s*', '', cleaned)
            cleaned = re.sub(r'^```\s*', '', cleaned)
            cleaned = re.sub(r'\s*```$', '', cleaned)
            cleaned = cleaned.strip()

            # ── Fix invalid LaTeX backslash escapes BEFORE json.loads ──────
            cleaned = self._fix_invalid_escapes(cleaned)

            questions = json.loads(cleaned)

            if not isinstance(questions, list):
                raise ValueError("Output must be a JSON array")

            validated_questions = []
            for q in questions:
                try:
                    validated = QuestionModel(**q)
                    validated_questions.append(validated.dict())
                except Exception as e:
                    print(f"⚠️  Validation error for question: {e}")
                    continue

            if not validated_questions:
                raise ValueError("No valid questions generated")

            return validated_questions

        except json.JSONDecodeError as e:
            raise Exception(
                f"Invalid JSON output from AI: {str(e)}\n\nOutput: {llm_output[:500]}"
            )
        except Exception as e:
            raise Exception(f"Validation failed: {str(e)}")


# ========================
# HELPER FUNCTIONS
# ========================

def generate_questions(
    mode: str,
    config: Dict,
    pdf_path: Optional[str] = None,
    topic: Optional[str] = None
) -> List[Dict]:
    """
    Main function to generate questions.
    mode: 'extract' | 'mine' | 'pure'
    """
    try:
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

    except Exception as e:
        raise Exception(f"Question generation failed: {str(e)}")