namespace AuthApi.Dtos
{
    public class UserDto
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
        public required string Email { get; set; }
    }
}