-- =============================================================================
-- SCRIPT T-SQL IDEMPOTENT UNIQUE - MKT Track (100 % SQL Server, ALCOA+)
-- Aucun fichier Excel / disque : comptes, configuration et Audit Trail sont dans SQL Server.
-- =============================================================================
SET NOCOUNT ON;
GO

-- 1. Comptes (mot de passe : PBKDF2-SHA256 sale, calcule cote serveur)
--    RoleName = 'ADMIN' ou identifiant du service (profil) de l'operateur.
IF OBJECT_ID('dbo.Users', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.Users (
        UserId INT IDENTITY(1,1) CONSTRAINT PK_Users PRIMARY KEY,
        Username NVARCHAR(100) NOT NULL CONSTRAINT UQ_Users_Username UNIQUE,
        PasswordHash NVARCHAR(256) NOT NULL,
        FullName NVARCHAR(150) NOT NULL,
        RoleName NVARCHAR(50) NOT NULL,
        IsActive BIT NOT NULL CONSTRAINT DF_Users_IsActive DEFAULT (1),
        CreatedAt DATETIMEOFFSET(7) NOT NULL CONSTRAINT DF_Users_CreatedAt DEFAULT (SYSDATETIMEOFFSET())
    );
END
GO

-- 2. Configuration unique (services, equipements, limites, branding, regles) au format JSON
IF OBJECT_ID('dbo.AppConfig', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.AppConfig (
        Id INT NOT NULL CONSTRAINT PK_AppConfig PRIMARY KEY CHECK (Id = 1),
        ConfigJson NVARCHAR(MAX) NOT NULL,
        UpdatedAt DATETIMEOFFSET(7) NOT NULL CONSTRAINT DF_AppConfig_UpdatedAt DEFAULT (SYSDATETIMEOFFSET())
    );
END
GO

-- 3. Version de configuration / audit (synchronisation multi-postes LAN)
IF OBJECT_ID('dbo.AppVersion', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.AppVersion (
        Id INT NOT NULL CONSTRAINT PK_AppVersion PRIMARY KEY CHECK (Id = 1),
        VersionNumber BIGINT NOT NULL,
        LastModifiedAt DATETIMEOFFSET(7) NOT NULL
    );
    INSERT INTO dbo.AppVersion (Id, VersionNumber, LastModifiedAt)
    VALUES (1, 1, SYSDATETIMEOFFSET());
END
GO

-- 4. Audit Trail ajout-seul, chaine par SHA-256 (EventId = numero de sequence)
IF OBJECT_ID('dbo.AuditTrail', 'U') IS NULL
BEGIN
    CREATE TABLE dbo.AuditTrail (
        EventId BIGINT IDENTITY(1,1) CONSTRAINT PK_AuditTrail PRIMARY KEY,
        EventTimestamp DATETIMEOFFSET(7) NOT NULL CONSTRAINT DF_AuditTrail_Timestamp DEFAULT (SYSDATETIMEOFFSET()),
        ClientTimestamp NVARCHAR(30) NOT NULL,
        Actor NVARCHAR(150) NOT NULL,
        Service NVARCHAR(100) NOT NULL,
        Action NVARCHAR(100) NOT NULL,
        Details NVARCHAR(500) NOT NULL,
        PrevHash NVARCHAR(64) NOT NULL,
        EntryHash NVARCHAR(64) NOT NULL,
        CorrelationId NVARCHAR(100) NOT NULL
    );
    CREATE NONCLUSTERED INDEX IX_AuditTrail_EventTimestamp ON dbo.AuditTrail (EventTimestamp DESC);
END
GO

-- 5. Immuabilite stricte de dbo.AuditTrail (21 CFR Part 11 / Annexe 11 / ALCOA+)
CREATE OR ALTER TRIGGER dbo.TR_AuditTrail_Immutable
ON dbo.AuditTrail
INSTEAD OF UPDATE, DELETE
AS
BEGIN
    SET NOCOUNT ON;
    RAISERROR ('ERREUR SECURITE SQL [TR_AuditTrail_Immutable] : Toute modification (UPDATE) ou suppression (DELETE) est strictement interdite sur la table dbo.AuditTrail (Exigence ALCOA+).', 16, 1);
    ROLLBACK TRANSACTION;
END
GO
