
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;

namespace FinalProjectSite.Controllers
{
    public class ContactUsController : Controller
    {
        public ActionResult ContactUs()
        {
            return View();
        }


        [HttpPost]
        public ActionResult ContactUs(string Name, string EmailId, string Subject, string Message)
        {
            try
            {
                MailMessage mail = new MailMessage();
                mail.To.Add("onlinesecsolution@gmail.com");
                mail.From = new MailAddress(EmailId);
                mail.Subject = Subject;

                string userMessage = "";
                userMessage = "<br/>Name -" + Name;
                userMessage = userMessage + "<br/>Email Address- " + EmailId;
                userMessage = userMessage + "<br/>Message- " + Message;
                string Body = "A User has sent an enquiry- " + userMessage + "<br/><br/>Reply when possible then delete this email to save space in the Email Inbox.";


                mail.Body = Body;
                mail.IsBodyHtml = true;

                SmtpClient smtp = new SmtpClient();
                //SMTP Server Address of gmail
                smtp.Host = "smtp.gmail.com";
                smtp.Port = 587;
                smtp.Credentials = new System.Net.NetworkCredential("onlinesecsolution@gmail.com", "BrightonUniversity1");
                // Smtp Email ID and Password For authentication
                smtp.EnableSsl = true;
                smtp.Send(mail);
                ViewBag.Message = "Thank you for contacting us. Your message and details have been saved. We will reply by sending you an email to the email address you provided.";
            }
            catch
            {
                ViewBag.Message = "Error!";
            }

            return View();
        }
    }


}
