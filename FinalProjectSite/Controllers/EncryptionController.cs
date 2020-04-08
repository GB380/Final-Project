using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace FinalProjectSite.Controllers
{
    public class EncryptionController : Controller
    {
        // GET: Encryption
        [Authorize]
        public ActionResult Encryption()
        {
            return View();
        }
    }
}