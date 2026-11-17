/*
    Tiresias per-lease SQL logins: schema, roles, signed procedures, provisioner (PRD 999, phase 2).

    Run with sqlcmd (SQLCMD mode in SSMS) as a sysadmin, once per instance and target database.
    Nothing in the broker runs this script; it is provisioning, applied by an administrator by hand. It is
    idempotent: running it again re-creates the procedures and re-signs them, and leaves existing
    logins, leases and certificates alone.

        sqlcmd -S <host> -E -i 01-tiresias-setup.sql ^
            -v Database="AppDb" ProvisionerPassword="<random>" SigningCertPassword="<random>"

    What it builds:
      - tir.Lease: one row per temporary login, with its expiry.
      - Roles tir_read (db_datareader) and tir_write (db_datareader + db_datawriter). No DDL, ever.
      - tir.BeginLease / tir.EndLease / tir.DropLogins, signed with the certificate tiresias_signing.
        The certificate's copy in master backs the login tiresias_signer, which alone holds
        ALTER ANY LOGIN, ALTER ANY CONNECTION and VIEW SERVER STATE. Module signing gives those
        rights to the procedures (including their dynamic SQL) and to nobody who calls anything else;
        there is no TRUSTWORTHY and no EXECUTE AS.
      - The login tiresias_provisioner, whose only permission is EXECUTE on tir.BeginLease and
        tir.EndLease. That is the credential the broker's vault holds for this instance.

    Naming: temporary logins are tir_<leaseId>_<grant> (e.g. tir_3f9a0c1d2e4b5a69_read). The service
    principals deliberately start with "tiresias_", not "tir_", so the cleanup job and the logon
    trigger's tir_% pattern never touch them.

    One target database per instance: orphan cleanup only drops tir_% logins whose default database
    is this one, so a second database with its own tir schema on the same instance stays separate.

    Hardening after setup (optional): ALTER CERTIFICATE tiresias_signing REMOVE PRIVATE KEY in
    $(Database). Nobody can sign another procedure with it after that, but re-running this script
    then needs a fresh certificate (drop the signatures, both certificate copies and
    tiresias_signer, and run again).
*/
:on error exit
SET NOCOUNT ON;
GO

------------------------------------------------------------------------------------------------
-- 1. master: the provisioner login (SQL authentication; its password goes into the vault).
------------------------------------------------------------------------------------------------
USE master;
GO
IF SUSER_ID(N'tiresias_provisioner') IS NULL
    CREATE LOGIN tiresias_provisioner
        WITH PASSWORD = N'$(ProvisionerPassword)', CHECK_EXPIRATION = OFF, CHECK_POLICY = ON,
             DEFAULT_DATABASE = [$(Database)];
GO

------------------------------------------------------------------------------------------------
-- 2. The target database: schema, lease table, roles, signing certificate, procedures.
------------------------------------------------------------------------------------------------
USE [$(Database)];
GO
IF SCHEMA_ID(N'tir') IS NULL
    EXEC (N'CREATE SCHEMA tir AUTHORIZATION dbo;');
GO
IF OBJECT_ID(N'tir.Lease', N'U') IS NULL
    CREATE TABLE tir.Lease
    (
        LoginName sysname      NOT NULL CONSTRAINT PK_tir_Lease PRIMARY KEY,
        LeaseId   varchar(32)  NOT NULL,
        GrantName varchar(16)  NOT NULL,
        CreatedAt datetime2(0) NOT NULL,
        ExpiresAt datetime2(0) NOT NULL,
        INDEX IX_tir_Lease_LeaseId (LeaseId),
        INDEX IX_tir_Lease_ExpiresAt (ExpiresAt)
    );
GO
IF DATABASE_PRINCIPAL_ID(N'tir_read') IS NULL
    CREATE ROLE tir_read AUTHORIZATION dbo;
IF DATABASE_PRINCIPAL_ID(N'tir_write') IS NULL
    CREATE ROLE tir_write AUTHORIZATION dbo;
GO
IF IS_ROLEMEMBER(N'db_datareader', N'tir_read') = 0
    ALTER ROLE db_datareader ADD MEMBER tir_read;
IF IS_ROLEMEMBER(N'db_datareader', N'tir_write') = 0
    ALTER ROLE db_datareader ADD MEMBER tir_write;
IF IS_ROLEMEMBER(N'db_datawriter', N'tir_write') = 0
    ALTER ROLE db_datawriter ADD MEMBER tir_write;
GO
IF CERT_ID(N'tiresias_signing') IS NULL
    CREATE CERTIFICATE tiresias_signing
        ENCRYPTION BY PASSWORD = N'$(SigningCertPassword)'
        WITH SUBJECT = N'Tiresias module signing', EXPIRY_DATE = N'2099-12-31';
GO

/*
    tir.DropLogins: kills the sessions of, and drops, temporary logins.
      @LeaseId set:  every login of that lease (lease end).
      @LeaseId NULL: every expired login, plus every tir_% login defaulting to this database that has
                     no tir.Lease row at all (left over from a crash between CREATE LOGIN and INSERT,
                     or a hand-made one). Run by the cleanup job.
    Signed, so that it holds the signer's server rights when tir.EndLease calls it (a signature's
    rights do not flow into an unsigned inner module). Not granted to anyone.
*/
CREATE OR ALTER PROCEDURE tir.DropLogins
    @LeaseId varchar(32) = NULL
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    DECLARE @Doomed TABLE (LoginName sysname PRIMARY KEY);
    INSERT @Doomed (LoginName)
    SELECT LoginName FROM tir.Lease
    WHERE (@LeaseId IS NOT NULL AND LeaseId = @LeaseId)
       OR (@LeaseId IS NULL AND ExpiresAt <= SYSUTCDATETIME());

    IF @LeaseId IS NULL
        INSERT @Doomed (LoginName)
        SELECT sp.name
        FROM sys.server_principals AS sp
        WHERE sp.type = 'S'
          AND sp.name LIKE N'tir[_]%'
          AND sp.default_database_name = DB_NAME()
          AND NOT EXISTS (SELECT 1 FROM tir.Lease AS l WHERE l.LoginName = sp.name)
          AND NOT EXISTS (SELECT 1 FROM @Doomed AS d WHERE d.LoginName = sp.name);

    DECLARE @Login sysname, @Session int, @Sql nvarchar(max);
    DECLARE doomed CURSOR LOCAL FAST_FORWARD FOR SELECT LoginName FROM @Doomed;
    OPEN doomed;
    FETCH NEXT FROM doomed INTO @Login;
    WHILE @@FETCH_STATUS = 0
    BEGIN
        -- A login with open sessions can't be dropped, and an open session would outlive the lease.
        DECLARE sessions CURSOR LOCAL FAST_FORWARD FOR
            SELECT session_id FROM sys.dm_exec_sessions WHERE login_name = @Login AND session_id <> @@SPID;
        OPEN sessions;
        FETCH NEXT FROM sessions INTO @Session;
        WHILE @@FETCH_STATUS = 0
        BEGIN
            SET @Sql = N'KILL ' + CAST(@Session AS nvarchar(11)) + N';';
            EXEC (@Sql);
            FETCH NEXT FROM sessions INTO @Session;
        END;
        CLOSE sessions;
        DEALLOCATE sessions;

        IF DATABASE_PRINCIPAL_ID(@Login) IS NOT NULL
        BEGIN
            SET @Sql = N'DROP USER ' + QUOTENAME(@Login) + N';';
            EXEC (@Sql);
        END;
        IF SUSER_ID(@Login) IS NOT NULL
        BEGIN
            SET @Sql = N'DROP LOGIN ' + QUOTENAME(@Login) + N';';
            EXEC (@Sql);
        END;
        DELETE tir.Lease WHERE LoginName = @Login;

        FETCH NEXT FROM doomed INTO @Login;
    END;
    CLOSE doomed;
    DEALLOCATE doomed;
END;
GO

/*
    tir.BeginLease: creates tir_<leaseId>_<grant> with a random password, in the grant's fixed role,
    expiring at @ExpiresAt (UTC, at most 10 hours away: the workday hard cap). The password is
    generated here, returned once, and stored nowhere in SQL Server but the login's hash.
*/
CREATE OR ALTER PROCEDURE tir.BeginLease
    @LeaseId   varchar(32),
    @Grant     varchar(16),
    @ExpiresAt datetime2(0),
    @Login     sysname       OUTPUT,
    @Password  nvarchar(128) OUTPUT
AS
BEGIN
    SET NOCOUNT ON;
    SET XACT_ABORT ON;

    IF @LeaseId IS NULL OR LEN(@LeaseId) NOT BETWEEN 8 AND 32
       OR @LeaseId COLLATE Latin1_General_BIN2 LIKE '%[^0-9a-f]%'
        THROW 50001, N'LeaseId must be 8 to 32 lower-case hex digits.', 1;

    DECLARE @Role sysname = CASE @Grant COLLATE Latin1_General_BIN2
        WHEN 'read' THEN N'tir_read'
        WHEN 'write' THEN N'tir_write'
    END;
    IF @Role IS NULL
        THROW 50002, N'Grant must be read or write.', 1;

    DECLARE @Now datetime2(0) = SYSUTCDATETIME();
    IF @ExpiresAt IS NULL OR @ExpiresAt <= @Now OR @ExpiresAt > DATEADD(HOUR, 10, @Now)
        THROW 50003, N'ExpiresAt must be within the next 10 hours (UTC).', 1;

    SET @Login = N'tir_' + @LeaseId + N'_' + @Grant;
    IF SUSER_ID(@Login) IS NOT NULL OR EXISTS (SELECT 1 FROM tir.Lease WHERE LoginName = @Login)
        THROW 50004, N'A login for this lease and grant already exists.', 1;

    -- 'Cb!' + 96 hex digits + 'x': upper, symbol, digits and lower, so CHECK_POLICY accepts it.
    SET @Password = N'Cb!' + CONVERT(nvarchar(96), CRYPT_GEN_RANDOM(48), 2) + N'x';

    DECLARE @Sql nvarchar(max);
    BEGIN TRANSACTION;
        SET @Sql = N'CREATE LOGIN ' + QUOTENAME(@Login)
            + N' WITH PASSWORD = ' + QUOTENAME(@Password, N'''')
            + N', CHECK_EXPIRATION = OFF, CHECK_POLICY = ON, DEFAULT_DATABASE = ' + QUOTENAME(DB_NAME()) + N';';
        EXEC (@Sql);
        SET @Sql = N'CREATE USER ' + QUOTENAME(@Login) + N' FOR LOGIN ' + QUOTENAME(@Login) + N';';
        EXEC (@Sql);
        SET @Sql = N'ALTER ROLE ' + QUOTENAME(@Role) + N' ADD MEMBER ' + QUOTENAME(@Login) + N';';
        EXEC (@Sql);
        INSERT tir.Lease (LoginName, LeaseId, GrantName, CreatedAt, ExpiresAt)
        VALUES (@Login, @LeaseId, @Grant, @Now, @ExpiresAt);
    COMMIT;
END;
GO

/* tir.EndLease: drops every temporary login of the lease. Idempotent: an unknown lease drops nothing. */
CREATE OR ALTER PROCEDURE tir.EndLease
    @LeaseId varchar(32)
AS
BEGIN
    SET NOCOUNT ON;
    IF @LeaseId IS NULL OR LEN(@LeaseId) NOT BETWEEN 8 AND 32
       OR @LeaseId COLLATE Latin1_General_BIN2 LIKE '%[^0-9a-f]%'
        THROW 50001, N'LeaseId must be 8 to 32 lower-case hex digits.', 1;
    EXEC tir.DropLogins @LeaseId = @LeaseId;
END;
GO

/* tir.DropExpired: the cleanup job's entry point. Runs as the job owner, so it needs no signature. */
CREATE OR ALTER PROCEDURE tir.DropExpired
AS
BEGIN
    SET NOCOUNT ON;
    EXEC tir.DropLogins @LeaseId = NULL;
END;
GO

-- CREATE OR ALTER drops a module's signature, so sign on every run.
IF NOT EXISTS (SELECT 1 FROM sys.crypt_properties WHERE major_id = OBJECT_ID(N'tir.DropLogins'))
    ADD SIGNATURE TO tir.DropLogins BY CERTIFICATE tiresias_signing WITH PASSWORD = N'$(SigningCertPassword)';
IF NOT EXISTS (SELECT 1 FROM sys.crypt_properties WHERE major_id = OBJECT_ID(N'tir.BeginLease'))
    ADD SIGNATURE TO tir.BeginLease BY CERTIFICATE tiresias_signing WITH PASSWORD = N'$(SigningCertPassword)';
IF NOT EXISTS (SELECT 1 FROM sys.crypt_properties WHERE major_id = OBJECT_ID(N'tir.EndLease'))
    ADD SIGNATURE TO tir.EndLease BY CERTIFICATE tiresias_signing WITH PASSWORD = N'$(SigningCertPassword)';
GO

-- The certificate's database user: the in-database half of the signature's rights.
IF DATABASE_PRINCIPAL_ID(N'tiresias_signer') IS NULL
    CREATE USER tiresias_signer FROM CERTIFICATE tiresias_signing;
GRANT ALTER ANY USER TO tiresias_signer;
GRANT ALTER ON ROLE::tir_read TO tiresias_signer;
GRANT ALTER ON ROLE::tir_write TO tiresias_signer;
GO

-- The provisioner may call the two entry points and nothing else.
IF DATABASE_PRINCIPAL_ID(N'tiresias_provisioner') IS NULL
    CREATE USER tiresias_provisioner FOR LOGIN tiresias_provisioner;
GRANT EXECUTE ON OBJECT::tir.BeginLease TO tiresias_provisioner;
GRANT EXECUTE ON OBJECT::tir.EndLease TO tiresias_provisioner;
GO

------------------------------------------------------------------------------------------------
-- 3. master: the certificate's copy (public key only) and the login its server rights hang on.
------------------------------------------------------------------------------------------------
DECLARE @Encoded varbinary(max) = CERTENCODED(CERT_ID(N'tiresias_signing'));
DECLARE @Thumbprint varbinary(32) = (SELECT thumbprint FROM sys.certificates WHERE name = N'tiresias_signing');
DECLARE @Sql nvarchar(max) = N'
USE master;
IF CERT_ID(N''tiresias_signing'') IS NULL
    CREATE CERTIFICATE tiresias_signing FROM BINARY = ' + CONVERT(nvarchar(max), @Encoded, 1) + N';
IF (SELECT thumbprint FROM sys.certificates WHERE name = N''tiresias_signing'') <> ' + CONVERT(nvarchar(max), @Thumbprint, 1) + N'
    THROW 50010, N''master holds a different tiresias_signing certificate; drop it and tiresias_signer, then rerun.'', 1;
IF SUSER_ID(N''tiresias_signer'') IS NULL
    CREATE LOGIN tiresias_signer FROM CERTIFICATE tiresias_signing;
GRANT ALTER ANY LOGIN TO tiresias_signer;
GRANT ALTER ANY CONNECTION TO tiresias_signer;
GRANT VIEW SERVER STATE TO tiresias_signer;';
EXEC (@Sql);
GO

PRINT N'Tiresias schema ready in $(Database). Next: 02-tiresias-cleanup-job.sql, then (carefully) 03-tiresias-logon-trigger.sql.';
GO
