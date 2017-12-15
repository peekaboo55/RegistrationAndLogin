using RegistrationAndLogin.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Mail;
using System.Web;
using System.Web.Mvc;
using System.Web.Security;

namespace RegistrationAndLogin.Controllers
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
        public ActionResult Registration([Bind(Exclude = "IsEmailVerified,ActivationCode")] User user,Users users)
        {
            bool Status = false;
            string message = "";

            //Model Validation
            if (ModelState.IsValid)
            {
                #region // Email is alreadi exist               

                //Email is already Exist
                var isExist = IsEmailExist(users.EmailID);
                if(isExist)
                {
                    ModelState.AddModelError("EmailEx", "Email already Exist");
                    return View(user);
                }
                #endregion

                #region //Generate Activition Code

                users.Password = Crypto.Hash(users.Password);
                user.ConfirmPassword = Crypto.Hash(user.ConfirmPassword); // 
                #endregion
                users.IsEmailVerified = false;

                #region//Save Data to Database

                using (MyDatabaseEntities dc = new MyDatabaseEntities())
                {
                    dc.Users.Add(users);
                    dc.SaveChanges();

                    //Send Email to User
                    SendVerificationLinkEmail(users.EmailID, users.ActivationCode.ToString());
                    message = "Registration successfully done. Account activation link " +
                        "has been sent to your email id:" + users.EmailID;
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

        //Verify Account
        [HttpGet]
        public ActionResult VerifyAccount(string id)
        {
            bool Status = false;
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                dc.Configuration.ValidateOnSaveEnabled = false; // This line i have added here to acoid
                                                                //Confirm Password does not match issue on save changes
                var v = dc.Users.Where(a => a.ActivationCode == new Guid(id).FirstOrDefault());
                if (v != null)
                {
                    v.IsEmailVerified = true;
                    dc.SaveChanges();
                    Status = true;
                }
                else
                {
                    ViewBag.Messsage = "Invalid Request";
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
        public ActionResult Login(UserLogin login, string ReturnUrl="")
        {
            string message = "";
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == login.EmailID).FirstOrDefault();
                if(v != null)
                {
                    if (string.Compare(Crypto.Hash(login.password),v.Password) == 0)
                    {
                        int timeout = login.RememberMe ? 525600 : 1; // 525600 min = 1 year
                        var ticket = new FormsAuthenticationTicket(login.EmailID, login.RememberMe, timeout);
                        string encrypted = FormsAuthentication.Encrypt(ticket);
                        var cookie = new HttpCookie(FormsAuthentication.FormsCookieName, encrypted);
                        cookie.Expires = DateTime.Now.AddMinutes(timeout);
                        cookie.HttpOnly = true;
                        Response.Cookies.Add(cookie);


                        if(Url.IsLocalUrl(ReturnUrl))
                        {
                            return Redirect(ReturnUrl);
                        }
                        else
                        {
                            return RedirectToAction("index", "Home");
                        }
                    }
                    else
                    {
                        message = "Invalid credential provided";
                    }
                }
                else
                {
                    message = "Invalid credential provided";
                }
            }
                ViewBag.Massage = message;
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
        public bool IsEmailExist(string emailID)
        {
            using (MyDatabaseEntities dc = new MyDatabaseEntities())
            {
                var v = dc.Users.Where(a => a.EmailID == emailID).FirstOrDefault();
                return v != null;
            }
        }

        [NonAction]
        public void SendVerificationLinkEmail(string emailID, string activationCode)
        {
            var verifyUrl = "/User/VerifyAccount/" + activationCode;
            var link = Request.Url.AbsoluteUri.Replace(Request.Url.PathAndQuery, verifyUrl);

            var fromEmail = new MailAddress("dotnetawesom@gmail.com", "Dornet Awesome");
            var toEmail = new MailAddress(emailID);
            var fromEmailPassword = "************"; //Replace with actual password
            string subject = "Your account is successfully created!";

            string body = "<br></br> We are excited to tell you that your Dotnet Awesom account is " + 
                " Successfully create. Please click on the bellow link to verify your account" +
                " <br></br><a href='" + link + "'>" + link + "</a> ";

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
    } 
}