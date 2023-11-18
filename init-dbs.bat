@echo off
set "currentdir=%cd%"

cd admin-ui

dotnet IdentityExpress.Manager.UI.dll -migrate Configuration -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate ExtendedConfiguration -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate DataProtection -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate Operational -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate Audit -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate Saml -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer
dotnet IdentityExpress.Manager.UI.dll -migrate WsFed -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" -dbProvider SqlServer

dotnet IdentityExpress.Manager.UI.dll -migrate Identity -connectionString "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOUsers" -dbProvider SqlServer

cd "%currentdir%"

dotnet tool restore
dotnet sql-cache create "Server=.;Integrated Security=true;MultipleActiveResultSets=true;TrustServerCertificate=true;Database=GotSharpSSOConfig" dbo AspNetCoreCache