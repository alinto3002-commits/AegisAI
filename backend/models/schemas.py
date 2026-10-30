from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class FindingSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class AgentType(str, Enum):
    CODE_ANALYSIS = "Code Analysis Agent"
    SECURITY_VULNERABILITY = "Security Vulnerability Agent"
    REMEDIATION = "Remediation Agent"
    PR_SUMMARY = "PR Summary Agent"
    CONVERSATIONAL = "Conversational Code Assistant"

class CodeSubmission(BaseModel):
    code: str = Field(..., description="The source code to be reviewed")
    language: Optional[str] = Field("auto", description="Language: 'python', 'java', or 'auto' for automatic identification")
    filename: Optional[str] = Field(None, description="Optional source code filename")
    validate_syntax_only: Optional[bool] = Field(False, description="Whether to only validate syntax")

class SyntaxValidationResult(BaseModel):
    is_valid: bool
    language: str
    filename: str
    line_count: int
    error_message: Optional[str] = None
    error_line: Optional[int] = None
    error_column: Optional[int] = None
    ast_summary: Dict[str, Any] = Field(default_factory=dict)
    cyclomatic_complexity: int = 1

class RemediationSuggestion(BaseModel):
    explanation: str
    original_snippet: str
    corrected_snippet: str
    diff: str
    references: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    unit_test_code: Optional[str] = Field(None, description="Generated automated unit/regression test")

class Finding(BaseModel):
    id: str
    agent_type: AgentType
    category: str
    title: str
    description: str
    severity: FindingSeverity
    line_start: int
    line_end: int
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    language: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[RemediationSuggestion] = None

class PRReviewSummary(BaseModel):
    summary_markdown: str
    verdict: str  # APPROVED, CHANGES_REQUESTED, BLOCKING_SECURITY_RISK
    health_score: int  # 0 to 100
    risk_level: str  # Low, Moderate, High, Critical
    key_findings: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)

class AgentToolTelemetry(BaseModel):
    tool: str
    findings: int
    time_seconds: float
    status: str = "ok"

class AgentExecutionDetail(BaseModel):
    agent_name: str
    model: str = "openai/gpt-oss-120b"
    duration_seconds: float
    tools: List[AgentToolTelemetry] = Field(default_factory=list)
    knowledge_sections_used: List[str] = Field(default_factory=list)

class ReviewReport(BaseModel):
    id: str
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    filename: str
    language: str
    lines_of_code: int
    cyclomatic_complexity: int
    health_score: int
    verdict: str
    risk_level: str
    findings: List[Finding] = Field(default_factory=list)
    severity_counts: Dict[str, int] = Field(
        default_factory=lambda: {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    )
    category_counts: Dict[str, int] = Field(default_factory=dict)
    pr_summary: PRReviewSummary
    agent_execution_times: Dict[str, float] = Field(default_factory=dict)
    execution_details: List[AgentExecutionDetail] = Field(default_factory=list)

class ChatQuery(BaseModel):
    query: str
    code_context: Optional[str] = None
    language: Optional[str] = "python"
    findings_context: Optional[List[Dict[str, Any]]] = None
    history: Optional[List[Dict[str, str]]] = Field(default_factory=list)

class KnowledgeSearchResult(BaseModel):
    id: str
    title: str
    category: str
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None
    language: Optional[str] = None
    content: str
    relevance_score: float

class ChatResponse(BaseModel):
    answer: str
    sources: List[KnowledgeSearchResult] = Field(default_factory=list)
    suggested_followups: List[str] = Field(default_factory=list)

class KnowledgeBaseDocument(BaseModel):
    id: str
    title: str
    category: str
    owasp_id: Optional[str] = None
    cwe_id: Optional[str] = None
    language: Optional[str] = "general"
    content: str
    tags: List[str] = Field(default_factory=list)
    secure_example: Optional[str] = None
    vulnerable_example: Optional[str] = None
