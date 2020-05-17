using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.Data.Entity;
using System.Data.SqlClient;
using System.Linq;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using FinalProjectSite.Models;

namespace FinalProjectSite.Controllers
{
   
    public class ProfileController : Controller
    {
        // GET: Profile
        [Authorize(Users = "brackers123@googlemail.com")]
        public ActionResult Index(string search)
        {
            UserDatabaseEntities dc = new UserDatabaseEntities();
            var customers = from s in dc.Users
                            select s;
            if (!String.IsNullOrEmpty(search))
            {
                customers = customers.Where(s => s.Email_Address.Contains(search));
            }
            return View(customers.ToList());

        }
               
        

        // GET: Profile/Details/5
        [Authorize(Users = "brackers123@googlemail.com")]
        public ActionResult Details(int id)
        {
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                return View(dc.Users.Where(x => x.UserID == id).FirstOrDefault());
            }
                
        }

        //// GET: Profile/Create
        //public ActionResult Create()
        //{
        //    return View();
        //}

        //// POST: Profile/Create
        //[HttpPost]
        //public ActionResult Create(User user)
        //{
        //    try
        //    {
        //        // TODO: Add insert logic here
        //        using (UserDatabaseEntities dc = new UserDatabaseEntities())
        //        {
        //            dc.Users.Add(user);
        //            dc.SaveChanges();
        //        }

        //            return RedirectToAction("Index");
        ////    }
        ////    catch
        ////    {
        ////        return View();
        ////    }
        //}

        // GET: Profile/Edit/5
        public ActionResult Edit(int id)
        {
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                return View(dc.Users.Where(x => x.UserID == id).FirstOrDefault());
            }
        }

        // POST: Profile/Edit/5
        [Authorize(Users = "brackers123@googlemail.com")]
        [HttpPost]
        public ActionResult Edit(int id, User user)
        {
            try
            {
                using (UserDatabaseEntities dc = new UserDatabaseEntities())
                {
                    dc.Entry(user).State = EntityState.Modified;
                    dc.SaveChanges();
                }
                    // TODO: Add update logic here

                    return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Profile/Delete/5
        [Authorize(Users = "brackers123@googlemail.com")]
        public ActionResult Delete(int id)
        {
            using (UserDatabaseEntities dc = new UserDatabaseEntities())
            {
                return View(dc.Users.Where(x => x.UserID == id).FirstOrDefault());
            }
        }

        // POST: Profile/Delete/5
        [Authorize(Users = "brackers123@googlemail.com")]
        [HttpPost]
        public ActionResult Delete(int id, FormCollection collection)
        {
            try
            {
                using (UserDatabaseEntities dc = new UserDatabaseEntities())
                {
                    User user=dc.Users.Where(x => x.UserID == id).FirstOrDefault();
                    dc.Users.Remove(user);
                    dc.SaveChanges();
                    // TODO: Add delete logic here
                }
                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }
    }
}
