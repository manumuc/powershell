--create database
CREATE DATABASE DSM
USE MyAppDb

-- Create table
CREATE TABLE dbo.NOCList (ID INT IDENTITY PRIMARY KEY,SpyName varchar(MAX) NOT NULL,RealName varchar(MAX) NULL)

-- Add sample records to table
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('James Bond','Sean Connery')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Ethan Hunt','Tom Cruise')
INSERT dbo.NOCList (SpyName, RealName)
VALUES ('Jason Bourne','Matt Damon')

-- Create login for the web app and direct connection
CREATE LOGIN MyPublicUser WITH PASSWORD = 'MyPassword!';
ALTER LOGIN [MyPublicUser] with default_database = [MyAppDb];
CREATE USER [MyPublicUser] FROM LOGIN [MyPublicUser];
EXEC sp_addrolemember [db_datareader], [MyPublicUser];

-- Create login that should not be viewable to MyPublicUser
CREATE LOGIN MyHiddenUser WITH PASSWORD = 'MyPassword!';

-- Impersonate MyPublicUser
EXECUTE AS LOGIN = 'MyPublicUser'

-- List privileges
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
GO


-- Check if the login is part of public
SELECT IS_SRVROLEMEMBER ( 'Public' )

-- Check other assigned server roles
SELECT PRN.name,
srvrole.name AS [role] ,
Prn.Type_Desc
FROM sys.server_role_members membership
INNER JOIN (SELECT * FROM sys.server_principals WHERE type_desc='SERVER_ROLE') srvrole
ON srvrole.Principal_id= membership.Role_principal_id
INNER JOIN sys.server_principals PRN
ON PRN.Principal_id= membership.member_principal_id WHERE Prn.Type_Desc NOT IN ('SERVER_ROLE')


-- Revert back to sa
REVERT
