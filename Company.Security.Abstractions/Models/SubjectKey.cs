namespace Company.Security.Abstractions;

/// <summary>
/// 身分識別主鍵（租戶 + 本系統 Subject）
/// </summary>
public readonly record struct SubjectKey(Guid TenantId, Guid OurSubject);
