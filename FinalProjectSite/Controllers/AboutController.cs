using FinalProjectSite.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Net;

namespace FinalProjectSite.Controllers
{
    public class AboutController : Controller
    {
        // GET: About

        DataClasses objData;

        public AboutController()
        {
            objData = new DataClasses();
        }

        //
        // GET: /Reports/

        public ActionResult AboutUs()
        {
            var files = objData.GetFiles();
            return View(files);
        }


        public FileResult Download(string id)
        {
            int fid = Convert.ToInt32(id);
            var files = objData.GetFiles();
            string filename = (from f in files
                               where f.FileId == fid
                               select f.FilePath).First();
            string contentType = "application/pdf";
            //Parameters to file are
            //1. The File Path on the File Server
            //2. The content type MIME type
            //3. The parameter for the file save by the browser
            return File(filename, contentType, "Module_Information.pdf");
        }
       
    }
}
