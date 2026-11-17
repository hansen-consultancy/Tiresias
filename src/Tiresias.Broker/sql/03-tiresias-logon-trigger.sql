/*
    Tiresias logon trigger: rejects tir_% logins and tiresias_provisioner unless they connect from
    the broker (PRD 999, phase 2). A temporary login or a stolen provisioner password is then useless
    from anywhere else, even with 1433 reachable.

    !! A broken logon trigger locks EVERY login out of the instance, sysadmins included. !!
    Apply it last, on test before prod, with a way out already open:

    1. Make sure the Dedicated Admin Connection works. It bypasses logon triggers. It is local-only
       by default; to use it over the network:
           EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;
    2. Open a DAC session NOW and keep it open while testing (only one DAC session at a time):
           sqlcmd -S admin:<host> -E        (on the VM itself: sqlcmd -S admin:localhost -E)
    3. Run this script from a second, ordinary session:
           sqlcmd -S <host> -E -i 03-tiresias-logon-trigger.sql -v BrokerIps="203.0.113.10,100.64.0.10"
       BrokerIps is the comma-separated list of addresses the broker reaches SQL Server from, exactly
       as SQL Server sees them (ClientHost): the public egress IP, and/or the broker's NetBird IP if
       the instance is reached over NetBird. Check with
           SELECT client_net_address FROM sys.dm_exec_connections WHERE session_id = @@SPID;
       from the broker host before applying.
    4. Test, each from a new connection:
         - an ordinary login (yours)                     -> connects
         - a tir_ login from the broker                   -> connects
         - a tir_ login or tiresias_provisioner from elsewhere
                                                         -> fails, error 17892 "Logon failed for
                                                            login ... due to trigger execution"
    5. Way out, from the DAC session (or single-user mode: sqlservr -m -f, then sqlcmd -E):
           DISABLE TRIGGER tiresias_pin_client_host ON ALL SERVER;
       and once fixed:
           ENABLE TRIGGER tiresias_pin_client_host ON ALL SERVER;

    Idempotent: re-running replaces the trigger (e.g. with a new BrokerIps list). Not run by the broker.
    The trigger touches no table and parses EVENTDATA() only for the logins it pins, so it costs
    every other login one string comparison and cannot fail on a missing object.
*/
:on error exit
SET NOCOUNT ON;
GO
USE master;
GO
IF EXISTS (SELECT 1 FROM sys.server_triggers WHERE name = N'tiresias_pin_client_host')
    DROP TRIGGER tiresias_pin_client_host ON ALL SERVER;
GO
CREATE TRIGGER tiresias_pin_client_host
ON ALL SERVER
FOR LOGON
AS
BEGIN
    DECLARE @Login sysname = ORIGINAL_LOGIN();
    IF @Login LIKE N'tir[_]%' OR @Login = N'tiresias_provisioner'
    BEGIN
        DECLARE @Host nvarchar(128) = EVENTDATA().value('(/EVENT_INSTANCE/ClientHost)[1]', 'nvarchar(128)');
        IF @Host IS NULL OR CHARINDEX(N',' + @Host + N',', N',' + REPLACE(N'$(BrokerIps)', N' ', N'') + N',') = 0
            ROLLBACK;
    END;
END;
GO
