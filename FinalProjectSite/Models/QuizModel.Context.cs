﻿//------------------------------------------------------------------------------
// <auto-generated>
//     This code was generated from a template.
//
//     Manual changes to this file may cause unexpected behavior in your application.
//     Manual changes to this file will be overwritten if the code is regenerated.
// </auto-generated>
//------------------------------------------------------------------------------

namespace FinalProjectSite.Models
{
    using System;
    using System.Data.Entity;
    using System.Data.Entity.Infrastructure;
    using System.Data.Entity.Core.Objects;
    using System.Linq;
    
    public partial class UserDatabaseEntities1 : DbContext
    {
        public UserDatabaseEntities1()
            : base("name=UserDatabaseEntities1")
        {
        }
    
        protected override void OnModelCreating(DbModelBuilder modelBuilder)
        {
            throw new UnintentionalCodeFirstException();
        }
    
        public virtual DbSet<SEquiz> SEquizs { get; set; }
    
        public virtual ObjectResult<SEQuizP_Result> SEQuizP()
        {
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<SEQuizP_Result>("SEQuizP");
        }
    
        public virtual ObjectResult<SEquiz> Fun_Quiz()
        {
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<SEquiz>("Fun_Quiz");
        }
    
        public virtual ObjectResult<SEquiz> Fun_Quiz(MergeOption mergeOption)
        {
            return ((IObjectContextAdapter)this).ObjectContext.ExecuteFunction<SEquiz>("Fun_Quiz", mergeOption);
        }
    }
}
