using System.ComponentModel.DataAnnotations;

namespace API.DTOs
{
    public class RegisterDTOs
    {
        [Required]
        public string username { get; set; }
        [Required]
        public string password { get; set; }
    }
}