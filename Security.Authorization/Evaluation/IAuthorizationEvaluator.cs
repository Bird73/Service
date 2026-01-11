namespace Birdsoft.Security.Authorization.Evaluation;

public interface IAuthorizationEvaluator
{
    ValueTask<AuthorizationDecision> EvaluateAsync(
        AuthorizationRequest request,
        CancellationToken cancellationToken = default);
}
