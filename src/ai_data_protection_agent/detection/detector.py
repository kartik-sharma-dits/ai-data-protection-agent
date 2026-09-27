from presidio_analyzer import AnalyzerEngine
from presidio_analyzer.nlp_engine import NlpEngineProvider

from .custom_recognizers import ALL_CUSTOM_RECOGNIZERS
from .models import DetectedEntity


def _build_analyzer(language: str, model_name: str) -> AnalyzerEngine:
    config = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": language, "model_name": model_name}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=config).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=[language])
    for recognizer in ALL_CUSTOM_RECOGNIZERS:
        analyzer.registry.add_recognizer(recognizer)
    return analyzer


class PIIDetector:
    """Finds sensitive entities in text. Detection only — no policy, no sanitization."""

    def __init__(self, language: str = "en", model_name: str = "en_core_web_sm") -> None:
        self._language = language
        self._analyzer = _build_analyzer(language, model_name)

    def detect(self, text: str) -> list[DetectedEntity]:
        results = self._analyzer.analyze(text=text, language=self._language)
        return [
            DetectedEntity(
                entity_type=r.entity_type,
                text=text[r.start : r.end],
                start=r.start,
                end=r.end,
                confidence=r.score,
            )
            for r in results
        ]
