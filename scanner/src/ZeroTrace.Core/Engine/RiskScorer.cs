using ZeroTrace.Core.Models;

namespace ZeroTrace.Core.Engine;

/// <summary>
/// Transparently derives a recommendation from a finding. The logic is simple
/// and explainable on purpose: operators should be able to predict it.
/// </summary>
public static class RiskScorer
{
    public static Recommendation Recommend(RiskLevel risk, bool? signed)
    {
        // A valid signature lowers urgency by one notch (still worth a look).
        return risk switch
        {
            RiskLevel.Critical => Recommendation.Remove,
            RiskLevel.High => signed == true ? Recommendation.Review : Recommendation.Remove,
            RiskLevel.Medium => Recommendation.Review,
            _ => signed == true ? Recommendation.Ignore : Recommendation.Review
        };
    }
}
