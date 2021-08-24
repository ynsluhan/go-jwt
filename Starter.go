package Starter

import (
	"errors"
	"github.com/dgrijalva/jwt-go"
	"time"
)

// 一些常量
var (
	// token错误信息的定义
	// 是否过期的token err
	TokenExpired error = errors.New("Token过期")
	// 是否为激活的token
	TokenNotValidYet error = errors.New("Token不存在")
	// 是否是正确格式的token
	TokenMalformed error = errors.New("Token格式有误")
	// 是否有效的token
	TokenInvalid error = errors.New("不是有效的token")
	// 签名信息
	// 从配置文件中获取
	// SignKey = config.GetConf().GetString("TokenSecretKey")
)

/*
 * @Author yNsLuHan
 * @Description:载荷，可以加一些自己需要的信息  用户token中科院提取用户信息之类
 */
type CustomClaims struct {
	ID       int    `json:"userId"`   // 用户id
	Mobile   string `json:"mobile"`   // 手机号
	Avatar   string `json:"avatar"`   // 头像
	NickName string `json:"nickname"` // 昵称
	Openid   string `json:"openid"`   // openid
	jwt.StandardClaims
}

/**
 * @Author yNsLuHan
 * @Description: JWT 签名结构
 */
type JWT struct {
	SigningKey []byte
}

/**
 * @Author yNsLuHan
 * @Description: 新建一个jwt实例, 整个Jwt创建入口
 * @Time 2021-06-22 11:13:09
 * @return *JWT
 */
func NewJwt(signKey string) *JWT {
	// 创建实体类
	return &JWT{SigningKey: []byte(signKey)}
}

/**
 * @Author yNsLuHan
 * @Description: 生成一个token
 * @Time 2021-06-22 11:14:07
 * @receiver j
 * @param claims
 * @return string
 * @return error
 */
func (j *JWT) CreateToken(claims CustomClaims) (string, error) {
	// 生成token
	// 使用hs256加密算法， 将荷载按照一定的规则进行加密 组合成token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 返回token,err
	return token.SignedString(j.SigningKey)
}

/**
 * @Author yNsLuHan
 * @Description:  解析token
 * @Time 2021-06-22 11:14:32
 * @receiver j
 * @param tokenString
 * @return *CustomClaims
 * @return error
 */
func (j *JWT) ParseToken(tokenString string) (*CustomClaims, error) {
	// 解析token，  传入token，传入空的user结构体，
	var c CustomClaims
	token, err := jwt.ParseWithClaims(tokenString, &c, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	// 判断err
	if err != nil {
		if ve, ok := err.(*jwt.ValidationError); ok {
			// 判断token是否正确格式
			if ve.Errors&jwt.ValidationErrorMalformed != 0 {
				return nil, TokenMalformed
				// 判断token是否过期
			} else if ve.Errors&jwt.ValidationErrorExpired != 0 {
				// Token is expired
				return nil, TokenExpired
				// 是否激活
			} else if ve.Errors&jwt.ValidationErrorNotValidYet != 0 {
				return nil, TokenNotValidYet
				// 是否为有效
			} else {
				return nil, TokenInvalid
			}
		}
	}
	// 校验通过，返回user对象
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	// 校验不通过，返回无效token信息
	return nil, TokenInvalid
}

/**
 * @Author yNsLuHan
 * @Description: 更新token
 * @Time 2021-06-22 11:14:40
 * @receiver j
 * @param tokenString
 * @return string
 * @return error
 */
func (j *JWT) RefreshToken(tokenString string) (string, error) {
	jwt.TimeFunc = func() time.Time {
		return time.Unix(0, 0)
	}
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return j.SigningKey, nil
	})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		jwt.TimeFunc = time.Now
		claims.StandardClaims.ExpiresAt = time.Now().Add(1 * time.Hour).Unix()
		return j.CreateToken(*claims)
	}
	return "", TokenInvalid
}
