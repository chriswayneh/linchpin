"""Hypothesis profiles: default for CI, "stress" for local shake-out runs.

Run with: pytest --hypothesis-profile=stress
"""

from hypothesis import settings

settings.register_profile("stress", max_examples=2000, deadline=None)
