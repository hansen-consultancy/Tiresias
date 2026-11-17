/*
    Tiresias failsafe: a SQL Agent job that drops expired and orphaned tir_% logins every 5 minutes
    (PRD 999, phase 2). The broker drops a lease's logins itself at lease end (tir.EndLease); this job
    covers a broker that died mid-lease, so a temporary login never outlives its expiry by more than
    one run.

    Run after 01-tiresias-setup.sql, as a sysadmin, with the same Database variable. Idempotent:
    an existing job of the same name is replaced. Not run by the broker.

        sqlcmd -S <host> -E -i 02-tiresias-cleanup-job.sql -v Database="AppDb"

    The job runs as its owner (sa), which needs no signature; it calls tir.DropExpired only.
    SQL Agent must be running (it is off by default on Express, which has no Agent at all: there,
    schedule `sqlcmd -Q "EXEC [$(Database)].tir.DropExpired"` from Task Scheduler instead).
*/
:on error exit
SET NOCOUNT ON;
GO
USE msdb;
GO
DECLARE @Job sysname = N'Tiresias cleanup ($(Database))';

IF EXISTS (SELECT 1 FROM dbo.sysjobs WHERE name = @Job)
    EXEC dbo.sp_delete_job @job_name = @Job, @delete_unused_schedule = 1;

EXEC dbo.sp_add_job
    @job_name = @Job,
    @description = N'Drops expired and orphaned Tiresias tir_% logins. See tools/Tiresias.Broker/sql.',
    @owner_login_name = N'sa',
    @enabled = 1;

EXEC dbo.sp_add_jobstep
    @job_name = @Job,
    @step_name = N'tir.DropExpired',
    @subsystem = N'TSQL',
    @database_name = N'$(Database)',
    @command = N'EXEC tir.DropExpired;',
    @retry_attempts = 0,
    @on_success_action = 1,
    @on_fail_action = 2;

EXEC dbo.sp_add_jobschedule
    @job_name = @Job,
    @name = N'Every 5 minutes',
    @enabled = 1,
    @freq_type = 4,              -- daily
    @freq_interval = 1,
    @freq_subday_type = 4,       -- minutes
    @freq_subday_interval = 5,
    @active_start_time = 0;

EXEC dbo.sp_add_jobserver @job_name = @Job, @server_name = N'(local)';
GO
