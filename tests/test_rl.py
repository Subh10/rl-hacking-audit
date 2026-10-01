import pytest
from ai_auditor.rl import Episode,RLSafetyAuditor
def test_empty_rl_input_rejected():
    with pytest.raises(ValueError):RLSafetyAuditor().audit([])
def test_constraint_and_ood_flags():
    report=RLSafetyAuditor().audit([Episode(.8,.8,constraint_violations=1,ood_score=.9,reward_model_scores=[.8,.8])]);assert "CONSTRAINT_VIOLATIONS" in report.flags and "OUT_OF_DISTRIBUTION_BEHAVIOR" in report.flags
