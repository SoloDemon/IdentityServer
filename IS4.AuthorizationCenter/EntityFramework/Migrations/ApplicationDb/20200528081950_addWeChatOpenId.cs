using Microsoft.EntityFrameworkCore.Migrations;

namespace IS4.AuthorizationCenter.EntityFramework.Migrations.ApplicationDb
{
    public partial class addWeChatOpenId : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<string>(
                name: "WeChatOpenId",
                table: "AspNetUsers",
                maxLength: 100,
                nullable: true);
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "WeChatOpenId",
                table: "AspNetUsers");
        }
    }
}
