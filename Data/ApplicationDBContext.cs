using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using api.Models;
using Microsoft.EntityFrameworkCore;

namespace api.Data
{
    public class ApplicationDBContext : DbContext
    {
        public ApplicationDBContext(DbContextOptions dbContextOptions)
        : base(dbContextOptions)
        {

        }

        public DbSet<Furniture> Furniture { get; set; }
        public DbSet<Image> Image { get; set; }
        public DbSet<Category> Category { get; set; }
        public DbSet<Color> Color { get; set; }
        public DbSet<FurnitureColor> FurnitureColor { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            builder.Entity<FurnitureColor>().HasKey(fc => new { fc.FurnitureId, fc.ColorId });

            builder.Entity<Furniture>()
                .HasMany(p => p.Images)
                .WithOne(i => i.Furniture)
                .HasForeignKey(i => i.FurnitureId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<FurnitureColor>()
                .HasOne(fc => fc.Furniture)
                .WithMany(f => f.FurnitureColors)
                .HasForeignKey(fc => fc.FurnitureId)
                .OnDelete(DeleteBehavior.Cascade);

            builder.Entity<FurnitureColor>()
                .HasOne(fc => fc.Color)
                .WithMany(f => f.FurnitureColors)
                .HasForeignKey(fc => fc.ColorId)
                .OnDelete(DeleteBehavior.Cascade);
        }
    }
}