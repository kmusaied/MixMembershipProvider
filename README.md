MixMembershipProvider
=====================

New custom membership provider allows you to Mix SqlMembershipProvider &amp; ActiveDirectoryMembershipProvider at the same time base on roles

Assubmtions
-----------
1- Both Active Directory Users and Forms Authentication Users are stored in Database.

2- Your Application Use Membership Role Management.

3- Your Active Directory Users assigned to specific role/roles.


Getting Started
---------------

1- Add Active Directory ConnectionString 

    <add name="ADConnectionString" connectionString="LDAP://TO.DO" />

2- Add Providers to your membership web.config 

    <membership defaultProvider="MixMembershipProvider">
             <providers>
               <clear />
               <add name="MyADMembershipProvider" type="System.Web.Security.ActiveDirectoryMembershipProvider" connectionStringName="ADConnectionString" />
               <add name="MyAspNetSqlMembershipProvider" type="System.Web.Security.SqlMembershipProvider" connectionStringName="ConnectionString" enablePasswordRetrieval="true" enablePasswordReset="true" requiresQuestionAndAnswer="false" requiresUniqueEmail="true" passwordFormat="Encrypted" maxInvalidPasswordAttempts="5" passwordAttemptWindow="10" minRequiredPasswordLength="6" minRequiredNonalphanumericCharacters="0" applicationName="/" />
               <add name="MixMembershipProvider" type="KhaledLabs.MixMembershipProvider,example" adRoles="ADRole1,ADRole2" adAuthMode="Username" connectionStringName="MyADConnectionString" aDProviderName="MyADMembershipProvider" sqlProviderName="AspNetSqlMembershipProvider" applicationName="/" />
             </providers>
           </membership>

3- update default provider to be "MixMembershipProvider"

    <membership defaultProvider="MixMembershipProvider">


Configuration
----------------
MixMembershipProvider have the following configuration attributes:

 - **adRoles**: in this attribute you will specify roles of users who will be authenticated agents Active Directory. note that users who are not in the adRoles will be authenticated agents Database.
 -  **adAuthMode**: values can be "username"/"email"/"usernameOrEmail". 
 - **connectionStringName**: Active Directory connection string name. 
 - **aDProviderName**: Active Directory Provider Name
 - **sqlProviderName**: SQL Provider Name
  


