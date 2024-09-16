namespace VulnerableApp.Models
{
    public class Comment
    {
        public int Id { get; set; }
        public string Username { get; set; } = null!;
        public string Content { get; set; } = null!;
    }
}