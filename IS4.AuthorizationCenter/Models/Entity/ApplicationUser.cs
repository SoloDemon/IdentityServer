﻿using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace IS4.AuthorizationCenter.Models.Entity
{
    /// <summary>
    /// 自定义用户
    /// </summary>
    public class ApplicationUser : IdentityUser<Guid>
    {
        /// <summary>
        /// 真实姓名
        /// </summary>
        public string RealName { get; set; }

        /// <summary>
        /// 性别 0:男 1:女
        /// </summary>
        public byte Sex { get; set; } = 0;
        /// <summary>
        /// 年龄
        /// </summary>
        [MaxLength(3)]
        public int Age { get; set; }

        /// <summary>
        /// qq号
        /// </summary>
        [MaxLength(20)]
        public virtual int Qicq { get; set; }

        /// <summary>
        /// 省份
        /// </summary>
        [MaxLength(20)]
        public string Province { get; set; }

        /// <summary>
        /// 城市
        /// </summary>
        [MaxLength(20)]
        public string City { get; set; }

        /// <summary>
        /// 国家
        /// </summary>
        [MaxLength(20)]
        public string Country { get; set; }

        /// <summary>
        /// 头像
        /// </summary>
        [MaxLength(300)]
        public string Portrait { get; set; }

        /// <summary>
        /// 昵称
        /// </summary>
        [MaxLength(20)]
        public string NickName { get; set; }

        /// <summary>
        /// 微信开放id
        /// </summary>
        [MaxLength(100)]
        public string WeChatOpenId { get; set; }

        /// <summary>
        /// 是否删除
        /// </summary>
        public bool IsDelete { get; set; }

        /// <summary>
        /// 角色用户关系表
        /// </summary>
        public ICollection<ApplicationUserRole> UserRoles { get; set; }
    }
}
