using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.ComponentModel.DataAnnotations;

namespace FinalProjectSite.Models
{
    [MetadataType(typeof(UserMetaData))]
    public partial class User
    {
        public string ConfirmPassword { get; set; }
    }

    public class UserMetaData
    {   [Display(Name ="First Name")]
        [Required(AllowEmptyStrings = false, ErrorMessage ="First Name Required")]
        public string First_Name { get; set; }


        [Display(Name = "Last Name")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "First Name Required")]
        public string Last_Name { get; set; }

        [Display(Name = "Email Address")]
        [Required(AllowEmptyStrings = false, ErrorMessage = "Email Address Required")]
        [DataType(DataType.EmailAddress)]
        public string Email_Address { get; set; }

        [Display(Name ="Date of Birth")]
        [DataType(DataType.Date)]
        [DisplayFormat(ApplyFormatInEditMode = true, DataFormatString ="{0:MM-dd-yyyy}")]
        public DateTime Date_of_Birth { get; set; }

        [Required(AllowEmptyStrings = false, ErrorMessage = "A Password is Required")]
        [DataType(DataType.Password)]
        [MinLength(6, ErrorMessage ="Password must contain a minimum of 6 characters")]
        public string Password { get; set; }

       [Display(Name ="Confirm Password")]
        [DataType(DataType.Password)]
        [Compare("Password", ErrorMessage ="Password and Confirm Password do not match.")]
        public string ConfirmPassword { get; set; }




    }

    
}