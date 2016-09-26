using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using Microsoft.Owin.Security;
using System.ComponentModel.DataAnnotations;
using System.Collections.Generic;
using Facebook;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;

namespace ExternalLogins_MVC5.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }
        public ActionResult ExternalLoginFailure()
        {
            return View();
        }
        public ActionResult ExternalLoginConfirmation()
        {
            return View();
        }
        public ActionResult GitHub()
        {
            return View();
        }
        private IAuthenticationManager AuthenticationManager
        {
            get { return HttpContext.GetOwinContext().Authentication; }
        }




        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public void ExternalLogin(string provider, string returnUrl = null)
        {
            var properties = new AuthenticationProperties { RedirectUri = Url.Action("ExternalLoginCallback", "Home", new { ReturnUrl = returnUrl }) };
            ControllerContext.HttpContext.GetOwinContext().Authentication.Challenge(properties, provider);

        }

        private string m_url;

        [JsonProperty("url")]
        public string ImageUrl
        {
            get { return m_url; }
            set { m_url = value; }
        }


        [HttpGet]
        [AllowAnonymous]
        public async Task<ActionResult> ExternalLoginCallback(string returnUrl = null)
        {
            ExternalLoginConfirmationViewModel model = new ExternalLoginConfirmationViewModel();
            var info = await AuthenticationManager.GetExternalLoginInfoAsync();

            if (info == null) { return RedirectToAction("Index", "Home"); }
            ViewBag.LoginProvider = info.Login.LoginProvider;

            if (info.Login.LoginProvider == "Facebook")
            {
                var identity = AuthenticationManager.GetExternalIdentity(DefaultAuthenticationTypes.ExternalCookie);
                var accessToken = identity.FindFirstValue("FacebookAccessToken");
                var fb = new FacebookClient(accessToken);
                dynamic email = fb.Get("me?fields=email");
                dynamic birthday = fb.Get("me?fields=birthday");
                dynamic name = fb.Get("me?fields=name");
                dynamic first_name = fb.Get("me?fields=first_name");
                dynamic last_name = fb.Get("me?fields=last_name");
                dynamic link = fb.Get("me?fields=link");
                dynamic gender = fb.Get("me?fields=gender");
                dynamic locale = fb.Get("me?fields=locale");
                //You can find other fields at https://developers.facebook.com/docs/graph-api/reference/user

                model = AddToModel(name.name, null, first_name.first_name, last_name.last_name, email.email, birthday.birthday, link.link, gender.gender, locale.locale, null, null, null);
            }
            else if (info.Login.LoginProvider == "Google")
            {
                string emailaddress = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").Value;
                string name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name").Value;
                string givenname = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname").Value;
                string surname = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname").Value;
                string url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:google:url").Value;
                string profile = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:google:profile").Value;
                //Profile and Url returns same value.
                string image = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:google:image").Value;
                var imageUrl = JsonConvert.DeserializeObject<HomeController>(image).ImageUrl;
                model = AddToModel(name, null, givenname, surname, emailaddress, null, url, null, null, null, null, imageUrl);
            }
            else if (info.Login.LoginProvider == "Microsoft")
            {
                string birth_day = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:birth_day").Value;
                string birth_month = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:birth_month").Value;
                string birth_year = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:birth_year").Value;
                string birthday = birth_month + "/" + birth_day + "/" + birth_year;
                string email = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Email).Value;
                string name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:name").Value;
                string first_name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:first_name").Value;
                string last_name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:last_name").Value;
                string link = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:link").Value;
                string gender = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:gender").Value;
                string locale = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:microsoft:locale").Value;

                model = AddToModel(name, null, first_name, last_name, email, birthday, link, gender, locale, null, null, null);
            }
            else if (info.Login.LoginProvider == "LinkedIn")
            {
                string id = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:id").Value;
                string imageUrl = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:pictureUrl").Value;
                string name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:name").Value;
                string formattedName = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:formattedName").Value;
                string firstName = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:firstName").Value;
                string lastName = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:lastName").Value;
                string emailAddress = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:emailAddress").Value;
                string headline = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:headline").Value;
                string url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:url").Value;
                string publicProfileUrl = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:linkedin:publicProfileUrl").Value;

                //You can find other fields at https://developer.linkedin.com/docs/fields/basic-profile

                model = AddToModel(name, formattedName, firstName, lastName, emailAddress, null, url, null, null, headline, publicProfileUrl, imageUrl);
            }
            else if (info.Login.LoginProvider == "Twitter")
            {
                string userid = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:twitter:userid").Value;
                string screenname = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:twitter:screenname").Value;

            }
            else if (info.Login.LoginProvider == "GitHub")
            {
                string name = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name").Value;
                string emailaddress = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress").Value;
                string url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:url").Value;
                string login = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:login").Value;
                string id = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:id").Value;
                string avatar_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:avatar_url").Value;
                string gravatar_id = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:gravatar_id").Value;
                string html_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:html_url").Value;
                string followers_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:followers_url").Value;
                string following_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:following_url").Value;
                string gists_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:gists_url").Value;
                string starred_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:starred_url").Value;
                string subscriptions_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:subscriptions_url").Value;
                string organizations_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:organizations_url").Value;
                string repos_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:repos_url").Value;
                string events_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:events_url").Value;
                string received_events_url = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:received_events_url").Value;
                string type = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:type").Value;
                string site_admin = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:site_admin").Value;
                string name2 = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:name").Value;
                string company = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:company").Value;
                string blog = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:blog").Value;
                string location = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:location").Value;
                string email = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:email").Value;
                string hireable = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:hireable").Value;
                string bio = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:bio").Value;
                string public_repos = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:public_repos").Value;
                string public_gists = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:public_gists").Value;
                string followers = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:followers").Value;
                string following = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:following").Value;
                string created_at = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:created_at").Value;
                string updated_at = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:updated_at").Value;
                string private_gists = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:private_gists").Value;
                string total_private_repos = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:total_private_repos").Value;
                string owned_private_repos = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:owned_private_repos").Value;
                string disk_usage = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:disk_usage").Value;
                string collaborators = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:collaborators").Value;
                string plan = info.ExternalIdentity.Claims.FirstOrDefault(c => c.Type == "urn:github:plan").Value;

                string[] git = new string[] { name, emailaddress, url, login, id, avatar_url, gravatar_id, html_url, followers_url, following_url, gists_url, starred_url, subscriptions_url, organizations_url, repos_url, events_url, received_events_url, type, site_admin, name2, company, blog, location, email, hireable, bio, public_repos, public_gists, followers, following, created_at, updated_at, private_gists, total_private_repos, owned_private_repos, disk_usage, collaborators, plan };
                return View("GitHub", git);
            }
            else
            {
                model.Email = null;
                model.BirthDate = null;
                model.FirstName = null;
                model.LastName = null;
            }
            return View("ExternalLoginConfirmation", model);
        }

        public ExternalLoginConfirmationViewModel AddToModel(string name, string formattedName, string firstName, string lastName, string email, string birthday, string link, string gender, string locale, string headline, string publicProfileUrl, string imageUrl)
        {
            var model = new ExternalLoginConfirmationViewModel();
            model.BirthDate = birthday;
            model.Email = email;
            model.FirstName = firstName;
            model.FormattedName = formattedName;
            model.Gender = gender;
            model.Headline = headline;
            model.LastName = lastName;
            model.Link = link;
            model.Locale = locale;
            model.Name = name;
            model.PublicProfileUrl = publicProfileUrl;
            model.ImageUrl = imageUrl;
            return model;
        }


        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        public ActionResult ExternalLoginConfirmation(ExternalLoginConfirmationViewModel model, string returnUrl = null)
        {
            //ToDo
            return View("Index");
        }


        public IEnumerable<SelectListItem> GetCountries()
        {
            List<SelectListItem> countryNames = new List<SelectListItem>();
            countryNames.Add(new SelectListItem { Text = "AAA", Value = "AAA" });
            countryNames.Add(new SelectListItem { Text = "BBB", Value = "BBB" });
            countryNames.Add(new SelectListItem { Text = "CCC", Value = "CCC" });
            countryNames.Add(new SelectListItem { Text = "DDD", Value = "DDD" });
            return countryNames;
        }

    }

    public class ExternalLoginConfirmationViewModel
    {
        [Required]
        [Display(Name = "Name (All)")]
        public string Name { get; set; }
        [Required]
        [Display(Name = "FormattedName (LinkedIn)")]
        public string FormattedName { get; set; }

        [Required]
        [Display(Name = "First Name (All)")]
        public string FirstName { get; set; }

        [Required]
        [Display(Name = "Last Name (All)")]
        public string LastName { get; set; }

        [Required]
        [EmailAddress]
        [Display(Name = "Email (All)")]
        public string Email { get; set; }

        [Required]
        [Display(Name = "BirthDate (Facebook, Microsoft)")]
        public string BirthDate { get; set; }

        [Required]
        [Display(Name = "Link (All)")]
        public string Link { get; set; }


        [Required]
        [Display(Name = "Gender (Facebook, Microsoft)")]
        public string Gender { get; set; }


        [Required]
        [Display(Name = "Locale (Facebook, Microsoft)")]
        public string Locale { get; set; }


        [Required]
        [Display(Name = "Headline (LinkedIn)")]
        public string Headline { get; set; }


        [Required]
        [Display(Name = "PublicProfileUrl (LinkedIn)")]
        public string PublicProfileUrl { get; set; }

        [Required]
        [Display(Name = "ImageUrl (Google, LinkedIn)")]
        public string ImageUrl { get; set; }
    }
}