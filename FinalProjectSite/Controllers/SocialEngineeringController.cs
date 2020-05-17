using FinalProjectSite.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace FinalProjectSite.Controllers
{
    [Authorize]
    public class SocialEngineeringController : Controller
    {
        // GET: SocialEngineering
        public ActionResult SocialEngineering()
        {
            return View();
        }

        public ActionResult SocialEngineeringTwo()
        {
            return View();
        }

        public ActionResult SocialEngineeringThree()
        {
            return View();
        }

        public ActionResult SocialEngineeringFour()
        {
            return View();

        }
        public ActionResult SocialEngineeringFive()
        {
            UserDatabaseEntities1 nd = new UserDatabaseEntities1();
                return View(nd.Fun_Quiz());

        }
    }
}