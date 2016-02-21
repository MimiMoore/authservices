﻿using Kentor.AuthServices.StubIdp.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace Kentor.AuthServices.StubIdp.Controllers
{
    public class DiscoveryServiceController : Controller
    {
        public ActionResult Index(DiscoveryServiceModel model)
        {
            if(model.isPassive || Request.HttpMethod == "POST")
            {
                string delimiter = model.@return.Contains("?") ? "&" : "?";

                return Redirect(FormattableString.Invariant($"{model.@return}{delimiter}{model.returnIDParam}={model.SelectedIdp}"));
            }

            return View(model);
        }
    }
}