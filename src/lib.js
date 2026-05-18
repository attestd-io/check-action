// Risk state severity order — higher number = more severe
const RISK_ORDER = { none: 0, low: 1, elevated: 2, high: 3, critical: 4 };

// Maps the fail_on input to the lowest risk_state that triggers failure
const FAIL_ON_THRESHOLD = {
  critical: "critical",
  high: "high",
  elevated: "elevated",
  any: "low",
  never: null,
};

function shouldFail(riskState, failOn, logger) {
  const threshold = FAIL_ON_THRESHOLD[failOn];
  if (threshold === null) return false;
  if (threshold === undefined) {
    if (logger?.warning) {
      logger.warning(
        `Unknown fail_on value: "${failOn}". Defaulting to "high".`
      );
    }
    return RISK_ORDER[riskState] >= RISK_ORDER["high"];
  }
  return RISK_ORDER[riskState] >= RISK_ORDER[threshold];
}

module.exports = { RISK_ORDER, FAIL_ON_THRESHOLD, shouldFail };
