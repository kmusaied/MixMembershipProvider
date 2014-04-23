using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;

namespace KhaledLabs
{
    public enum ADAuthModes
    {
        Username = 1,
        Email = 2,
        UsernameOrEmail = 3
    }
    public class MixMembershipProvider : System.Web.Security.MembershipProvider
    {
        private string[] ADRoles { get; set; }
        private ADAuthModes ADAuthMode { get; set; }
        private ActiveDirectoryMembershipProvider _ADProvider;
        private SqlMembershipProvider _SqlProvider;
        private const string missingPropertyErrorMessage = "'{0}' property must have a valid '{1}' membership provider name";

        #region Cache Helpers
        private void SetCache(string key , object obj)
        {
            HttpContext.Current.Cache[key] = obj;
        }

        private object GetCache(string key)
        {
            return HttpContext.Current.Cache[key];
        }
        #endregion


        public override void Initialize(string name, System.Collections.Specialized.NameValueCollection config)
        {
            base.Initialize(name, config);

            if (string.IsNullOrEmpty(config["adRoles"]))
                throw new ConfigurationErrorsException("'adRoles' property is missing; it must have a valid roles");
            ADRoles = config["adRoles"].Split(',');
            if (string.IsNullOrEmpty(config["adAuthMode"]))
                ADAuthMode = ADAuthModes.Username;
            else
                ADAuthMode = (ADAuthModes)Enum.Parse(typeof(ADAuthModes), config["adAuthMode"]);

            CacheADDomain();

        }

        private ActiveDirectoryMembershipProvider ADProvider
        {
            get
            {
                InitADProvider();
                return _ADProvider;
            }
        }

        private SqlMembershipProvider SqlProvider
        {
            get
            {
                InitSqlProvider();
                return _SqlProvider;

            }
        }

        private string ADDomain
        {
            get
            {
                CacheADDomain();
                return GetCache("ADDomain") as string;
            }
        }


        /// <summary>
        /// Returns true if the user have at least one AD Role
        /// </summary>
        /// <param name="username"></param>
        /// <returns>true/false</returns>
        private bool CheckIfUserIsAD(string username)
        {
            string[] userRoles = Roles.GetRolesForUser(username);
            return userRoles.Any(r => ADRoles.Contains(r));
        }

        private void CacheADDomain()
        {
            
            if (GetCache("ADDomain") == null)
            {
                string ldapConnectionString;

                MembershipSection membershipSection = GetConfigMembershipSection();

                if (membershipSection == null)
                    throw new ConfigurationErrorsException("Configuration Section 'system.web/membership' not found");

                string adProviderName = membershipSection.Providers[this.Name].Parameters["aDProviderName"];
                ldapConnectionString = ConfigurationManager.ConnectionStrings[membershipSection.Providers[adProviderName].Parameters["connectionStringName"]].ConnectionString;

                string reqex = @"([a-zA-Z0-9]+(\.[a-zA-Z0-9]+)+.*)$"; //regex to extract domain from the LDAP connectionstring
                SetCache(System.Text.RegularExpressions.Regex.Match(ldapConnectionString, reqex).Value, "ADDomain");
            }
            
        }


        private void InitADProvider()
        {
            MembershipSection membershipSection = GetConfigMembershipSection();

            if (membershipSection == null)
                throw new ConfigurationErrorsException("Configuration Section 'system.web/membership' not found");

            string adProviderName = membershipSection.Providers[this.Name].Parameters["aDProviderName"];

            _ADProvider = (ActiveDirectoryMembershipProvider)Membership.Providers[adProviderName];

        }

        private static MembershipSection GetConfigMembershipSection()
        {
            MembershipSection membershipSection = (MembershipSection)ConfigurationManager.GetSection("system.web/membership");
            if (membershipSection == null)
                throw new ConfigurationErrorsException("Configuration Section 'system.web/membership' not found");
            return membershipSection;
        }

        private void InitSqlProvider()
        {
            MembershipSection membershipSection = GetConfigMembershipSection();
            string sqlProviderName = membershipSection.Providers[this.Name].Parameters["sqlProviderName"];
            _SqlProvider = (SqlMembershipProvider)Membership.Providers[sqlProviderName];
            
        }


        #region Public Membership Methods
        public override bool ChangePassword(string username, string oldPassword, string newPassword)
        {
            if (!CheckIfUserIsAD(username))
                return SqlProvider.ChangePassword(username, oldPassword, newPassword);
            else
                throw new InvalidOperationException(string.Format("{0} is an AD User", username));
        }

        public override bool ChangePasswordQuestionAndAnswer(string username, string password, string newPasswordQuestion, string newPasswordAnswer)
        {
            if (!CheckIfUserIsAD(username))
                return SqlProvider.ChangePasswordQuestionAndAnswer(username, password, newPasswordQuestion, newPasswordAnswer);
            else
                throw new InvalidOperationException(string.Format("{0} is an AD User", username));
        }



        public override string GetPassword(string username, string answer)
        {
            if (!CheckIfUserIsAD(username))
                return SqlProvider.GetPassword(username, answer);
            else
                throw new InvalidOperationException(string.Format("Can't Get Password for '{0}' because it is an AD User", username));
        }

        public override string ResetPassword(string username, string answer)
        {
            if (!CheckIfUserIsAD(username))
                return SqlProvider.ResetPassword(username, answer);
            else
                throw new InvalidOperationException(string.Format(" Can't change password {0}' is an AD User", username));
        }


        public override bool ValidateUser(string username, string password)
        {
            if (!CheckIfUserIsAD(username))
                return SqlProvider.ValidateUser(username, password);
            else
            {
                switch (ADAuthMode)
                {
                    case ADAuthModes.Username:
                        return ADProvider.ValidateUser(string.Format("{0}@{1}",username,ADDomain), password);
                    case ADAuthModes.Email:
                        MembershipUser user = GetUser(username, true);
                        return ADProvider.ValidateUser(user.Email, password);
                    case ADAuthModes.UsernameOrEmail:
                        bool result = ADProvider.ValidateUser(string.Format("{0}@{1}", username, ADDomain), password);
                        if (!result)
                        {
                            MembershipUser user2 = GetUser(username, true);
                            result = ADProvider.ValidateUser(user2.Email, password);
                        }
                        return result;
                }

                return false;
            }

        }

        public override string ApplicationName
        {
            get { return SqlProvider.ApplicationName; }
            set { SqlProvider.ApplicationName = value; }
        }

        public override MembershipUser CreateUser(string username, string password, string email, string passwordQuestion, string passwordAnswer, bool isApproved, object providerUserKey, out MembershipCreateStatus status)
        {
            return SqlProvider.CreateUser(username, password, email, passwordQuestion, passwordAnswer, isApproved, providerUserKey, out status);
        }

        public override bool DeleteUser(string username, bool deleteAllRelatedData)
        {
            return SqlProvider.DeleteUser(username, deleteAllRelatedData);
        }

        public override bool EnablePasswordReset
        {
            get { return SqlProvider.EnablePasswordReset; }
        }

        public override bool EnablePasswordRetrieval
        {
            get { return SqlProvider.EnablePasswordRetrieval; }
        }

        public override MembershipUserCollection FindUsersByEmail(string emailToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return SqlProvider.FindUsersByEmail(emailToMatch, pageIndex, pageSize, out  totalRecords);
        }

        public override MembershipUserCollection FindUsersByName(string usernameToMatch, int pageIndex, int pageSize, out int totalRecords)
        {
            return SqlProvider.FindUsersByName(usernameToMatch, pageIndex, pageSize, out totalRecords);
        }

        public override MembershipUserCollection GetAllUsers(int pageIndex, int pageSize, out int totalRecords)
        {
            return SqlProvider.GetAllUsers(pageIndex, pageSize, out  totalRecords);
        }

        public override int GetNumberOfUsersOnline()
        {
            return SqlProvider.GetNumberOfUsersOnline();
        }

        public override MembershipUser GetUser(string username, bool userIsOnline)
        {
            return SqlProvider.GetUser(username, userIsOnline);
        }

        public override MembershipUser GetUser(object providerUserKey, bool userIsOnline)
        {
            return SqlProvider.GetUser(providerUserKey, userIsOnline);
        }

        public override string GetUserNameByEmail(string email)
        {
            return SqlProvider.GetUserNameByEmail(email);
        }

        public override int MaxInvalidPasswordAttempts
        {
            get { return SqlProvider.MaxInvalidPasswordAttempts; }
        }

        public override int MinRequiredNonAlphanumericCharacters
        {
            get { return SqlProvider.MinRequiredNonAlphanumericCharacters; }
        }

        public override int MinRequiredPasswordLength
        {
            get { return SqlProvider.MinRequiredPasswordLength; }
        }

        public override int PasswordAttemptWindow
        {
            get { return SqlProvider.PasswordAttemptWindow; }
        }

        public override MembershipPasswordFormat PasswordFormat
        {
            get { return SqlProvider.PasswordFormat; }
        }

        public override string PasswordStrengthRegularExpression
        {
            get { return SqlProvider.PasswordStrengthRegularExpression; }
        }

        public override bool RequiresQuestionAndAnswer
        {
            get { return SqlProvider.RequiresQuestionAndAnswer; }
        }

        public override bool RequiresUniqueEmail
        {
            get { return SqlProvider.RequiresUniqueEmail; }
        }

        public override bool UnlockUser(string userName)
        {
            return SqlProvider.UnlockUser(userName);
        }

        public override void UpdateUser(MembershipUser user)
        {
            SqlProvider.UpdateUser(user);
        }
        #endregion
    }
}
