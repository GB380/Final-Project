using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;
using FinalProjectSite.Models;

namespace FinalProjectSite.Controllers
{
    public class UserController : Controller
    {
       //Registration Action
       [HttpGet]
       public ActionResult Registration()
        {
            return View();
        }
        //Registration POST Action
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified,Activation_Code")]User user)
        {
            bool Status = false;
            string message = "";
            //
            //Model Validation
            if (ModelState.IsValid)
            {
                //Does Email Exist?
                #region //Email Already Exists
                var isExist = IsEmailExist(user.Email_Address);
                if (isExist)
                {
                    ModelState.AddModelError("EmailExist", "Email already exists");
                    return View(user);
                }
                #endregion
                // Generate Activation Code
                #region Generate Activation Code
                user.Activation_Code = Guid.NewGuid();
                #endregion

                // Password Hashing
                #region Password Hashing
                user.Password = Crypto.Hash(user.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword);
                #endregion
                user.IsEmailVerified = false;

                //Save Data to Database
                #region Save to Database
                using (UserDatabaseEntities dc = new UserDatabaseEntities())
                {
                    dc.Users.Add(user);
                    dc.SaveChanges(); 
                    //E:\Project Site\FinalProjectSite\FinalProjectSite\App_Data\UserDatabase.mdf
                    //Send Email to User
                    SendVerificationLinkEmail(user.Email_Address, user.Activation_Code.ToString());
                    message = "Registration Successful. Account activation link " +
                        " has been sent to your Email Address:" + user.Email_Address;
                    Status = true;
                }
                #endregion
            }
            else
            {
                message = "Invalid Request";
            }









            ViewBag.Message = message;
            ViewBag.Status = Status;
            return View(user);
        }

        //Verify Email Address
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; //This is to avoid confirm password does not match issue on save changes

                var v = dc.Users.Where(a => a.Activation_Code == new Guid(id)).FirstOrDefault();
                if (v != null)
                {
                    v.IsEmailVerified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Message = "Invalid Request";
                }
            }
            ViewBag.Status = Status;
            return View();
        }


        //Login
        [HttpGet]
        public ActionResult Login()
        {
            return View();
        }


        //Login POST
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(UserLogin login, string ReturnUrl)
        {
            string message = "";
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.Email_Address == login.Email_address).FirstOrDefault();
                if (v != null)
                {
                    if(string.Compare(Crypto.Hash(login.Password),v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 525600 : 20; //525600 min = 1year of remembering
                        var ticket = new FormsAuthenticationTicket(login.Email_address, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);


                        if (Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            return RedirectToAction("LoginWelcome", "Home");
                        }
                    }
                    else
                    {
                        message = "Invalid Credentials Provided";
                    }

                }
                else
                {
                    message = "Invalid Credentials Provided";
                }
            }
            ViewBag.Message = message;
            return View();
        }

        //Logout
        [Authorize]
        [HttpPost]
        public ActionResult Logout()
        {
            FormsAuthentication.SignOut();
            return RedirectToAction("Login", "User");
        }


        [NonAction]
        public bool IsEmailExist(string email_Address)
        {
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.Email_Address == email_Address).FirstOrDefault();
                return v != null;
            }
        }

        [NonAction]
        public void SendVerificationLinkEmail(string Email_Address, string activationcode, string emailFor = "VerifyAccount")
        {
            //Verify Email Link
            var verifyUrl = "/User/"+emailFor+"/" + activationcode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("onlinesecsolution@gmail.com", "Online Security Solutions");
            var toEmail = new MailAddress(Email_Address);
            var fromEmailPassword = "BrightonUniversity1"; //Password here

            string subject = "";
            string body = "";
            if (emailFor == "VerifyAccount")
            {
                subject = "Your account has been successfully created!";


                body = "<br/><br/> Your Online Security Solutions account has been " +
                    "successfully created. Please click on the below link to verify your account" +
                    "<br  /><a href=' " + link + "'>" + link + "</a> ";
            }
            else if (emailFor == "ResetPassword")
            {
                subject = "ResetPassword";
                body = "Hi, <br/>br/> We recieved a request to reset your password for your account. Please click on the below link to reset your password." +
                    "<br/><br/><a href="+link+">Reset Password Link</a>";
            }
       

            var smtp = new SmtpClient
            {
                Host = "smtp.gmail.com",
                Port = 587,
                EnableSsl = true,
            DeliveryMethod = SmtpDeliveryMethod.Network,
            UseDefaultCredentials = false,
            Credentials = new NetworkCredential(fromEmail.Address, fromEmailPassword)
            };

            using (var message = new MailMessage(fromEmail, toEmail)
            {
                Subject = subject,
                Body = body,
                IsBodyHtml = true
            })
                smtp.Send(message);

        }


        // Forgot Password

        public ActionResult ForgotPassword()
        {
            return View();
        }

        [HttpPost]
        public ActionResult ForgotPassword(string EmailAddress)
        {
            // verify Email Address
            // If Valid then generate Reset Password Link
            //Send Password Reset Email
            string message = "";
            bool status = false;


            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                var account = dc.Users.Where(a => a.Email_Address == EmailAddress).FirstOrDefault(); // Searches if there is an account already
                if (account != null)
                {
                    //send email for password reset
                    string resetCode = Guid.NewGuid().ToString();
                    SendVerificationLinkEmail(account.Email_Address, resetCode, "ResetPassword");
                    account.ResetPasswordCode = resetCode;
                    //Line added to avoid confirm password not matching issue, as the confirm password property that was added
                    // to the model class.
                    dc.Configuration.ValidateOnSaveEnabled = false;
                    dc.SaveChanges();
                    message = "The Reset Password Link has been sent to your Email Address.";
                }
                else
                {
                    message = "That Email Address has not been registered. Please try again or register for an Account";
                }
            }
            ViewBag.Message = message;
            return View();
        }
        

        public ActionResult ResetPassword(string id)
        {
            //Verify the reset password link
            //find account associated with the link
            //redirect to new password page
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                var user = dc.Users.Where(a => a.ResetPasswordCode == id).FirstOrDefault();
                if (user != null)
                {
                    ResetPasswordModel model = new ResetPasswordModel();
                    model.ResetCode = id;
                    return View(model);
                }
                else
                {
                    return HttpNotFound();
                }
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult ResetPassword(ResetPasswordModel model)
        {
            var message = "";
            if (ModelState.IsValid)
            {
                using  (UserDatabaseEntities dc = new UserDatabaseEntities())
                {
                    var user = dc.Users.Where(a => a.ResetPasswordCode == model.ResetCode).FirstOrDefault();
                    if (user != null)
                    {
                        user.Password = Crypto.Hash(model.NewPassword);
                        user.ResetPasswordCode = "";
                        dc.Configuration.ValidateOnSaveEnabled = false; // same password match issue
                        dc.SaveChanges();
                        message = "New Password Updated Successfully";
                    }
                }
            }
            else
            {
                message = "Password Reset Unsuccessful. Please contact an Administrator using the Contact Us Page.";
            }
            ViewBag.Message = message;
            return View(model);
        }
   

        

    }
   
}