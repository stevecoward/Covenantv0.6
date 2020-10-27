using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

using Covenant.Models;
using Covenant.Models.MitreTechniques;
using Covenant.Core;

namespace Covenant.Controllers
{
    [ApiController, Route("api/attack"), Authorize]
    public class AttackController : Controller
    {
        private readonly ICovenantService _service;

        public AttackController(ICovenantService service)
        {
            _service = service;
        }

        [HttpGet(Name = "Index")]
        public async Task<IActionResult> Index()
        {
            ViewBag.GruntTasks = await _service.GetGruntTasks();
            return View();
        }

        [HttpGet("task-techniques/{gruntTaskId:int}", Name = "GetMitreTechniquesForTask")]
        public async Task<JsonResult> GetMitreTechniquesForTask(int gruntTaskId)
        {
            List<MitreTechnique> results = new List<MitreTechnique>();

            foreach (var gruntTechniqueRecords in await _service.GetMitreTechniques(gruntTaskId))
            {
                results.Add(_service.GetMitreTechnique(gruntTechniqueRecords.MitreTechniqueId));
            }
            return Json(results);
        }

        [HttpGet("techniques", Name = "GetMitreTechniques")]
        public async Task<JsonResult> GetMitreTechniques()
        {
            return Json(await _service.GetMitreTechniques());
        }

        [HttpGet("techniques/{gruntTaskId:int}", Name = "GetMitreTechniquesByTaskId")]
        public async Task<JsonResult> GetMitreTechniquesByTaskId(int gruntTaskId)
        {
            return Json(await _service.GetMitreTechniques(gruntTaskId));
        }

        [HttpPost("assign/{mitreTechniqueId}/grunt-task/{gruntTaskId:int}", Name = "AssignMitreTechniqeToGruntTask")]
        [ProducesResponseType(typeof(MitreTechniqueGruntTask), 201)]
        [Route("attack/assign/{mitreTechniqueId}/grunt-task/{gruntTaskId:int}")]
        public async Task<JsonResult> AssignMitreTechniqeToGruntTask(string mitreTechniqueId, int gruntTaskId)
        {
            _service.AssignTechniqueToTask(mitreTechniqueId, gruntTaskId);
            return Json(_service.GetMitreTechniqueGruntTaskByGruntTask(gruntTaskId));
        }

        [HttpDelete("remove/{mitreTechniqueId}/grunt-task/{gruntTaskId:int}", Name = "RemoveMitreTechniqeGruntTask")]
        [ProducesResponseType(204)]
        public async Task<JsonResult> RemoveMitreTechniqeGruntTask(string mitreTechniqueId, int gruntTaskId)
        {
            _service.RemoveTechniqueFromTask(mitreTechniqueId, gruntTaskId);
            return Json(_service.GetMitreTechniqueGruntTaskByGruntTask(gruntTaskId));
        }
    }
}
