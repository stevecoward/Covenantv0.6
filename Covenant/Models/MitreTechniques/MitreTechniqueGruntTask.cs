using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Threading.Tasks;

namespace Covenant.Models.MitreTechniques
{
    public class MitreTechniqueGruntTask
    {
        [Key, DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        public int Id { get; set; }
        public string MitreTechniqueId { get; set; }
        public int GruntTaskId { get; set; }
        public virtual MitreTechnique MitreTechnique { get; set; }
    }
}
