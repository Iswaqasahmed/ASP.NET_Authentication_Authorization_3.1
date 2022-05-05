using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Threading.Tasks;
using System.Security.Claims;
using System.Linq;
using Microsoft.AspNetCore.Authentication.Google;

namespace ASP_NET_Core_3
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        //This method gets called by the runtime.Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme).AddCookie(
                options =>
                {
                    options.LoginPath = "/Login";
                    options.AccessDeniedPath = "/Denied";

                    options.Events = new CookieAuthenticationEvents()
                    {
                        OnSignedIn = async context =>
                        {
                            var principle = context.Principal;
                            if (principle.HasClaim(c => c.Type == ClaimTypes.NameIdentifier))
                            {
                                if (principle.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier).Value == "admin")
                                {
                                    var claimsIdentity = principle.Identity as ClaimsIdentity;
                                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, "admin"));
                                    //context.HttpContext.Response.Redirect("/Admin");
                                }
                            }
                            await Task.CompletedTask;
                            //context.HttpContext.Response.Redirect("/");
                            //return Task.CompletedTask;
                        },
                        OnSigningIn = async context => { await Task.CompletedTask; },
                        OnValidatePrincipal = async context => { await Task.CompletedTask; }

                        #region comment
                        //OnRedirectToLogin = context =>
                        //   {
                        //       if (context.Request.Path.StartsWithSegments("/api") &&
                        //           context.Response.StatusCode == 200)
                        //       {
                        //           context.Response.StatusCode = 401;
                        //       }
                        //       return Task.CompletedTask;
                        //   }
                        #endregion
                    };
                });
        }






        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.


        //public void ConfigureServices(IServiceCollection services)
        //{
        //    services.AddControllersWithViews();
        //    services.AddAuthentication(options => {
        //        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        //        options.DefaultChallengeScheme = GoogleDefaults.AuthenticationScheme;
        //    }).AddCookie(options =>
        //    { 
        //            options.LoginPath = "/login";
        //    options.AccessDeniedPath = "/denied";
        //     }).AddGoogle(options =>
        //     {
        //         options.ClientId = "258627838171-8ui3u1rirter67kgioes1unafl4j18vo.apps.googleusercontent.com";
        //         options.ClientSecret = "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";
        //         options.CallbackPath = "/auth";
        //      });
        //}


        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            // must added to pipe-line before UseAuthentication()
            app.UseAuthentication();

            app.UseAuthorization();


            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
