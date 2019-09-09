package guard

import (
	"github.com/chenhg5/go-admin/context"
	"html/template"
)

type MenuEditParam struct {
	Id       string
	Title    string
	ParentId string
	Icon     string
	Uri      string
	Roles    []string
	Alert    template.HTML
}

func (e MenuEditParam) HasAlert() bool {
	return e.Alert != template.HTML("")
}

func MenuEdit(ctx *context.Context) {

	parentId := ctx.FormValue("parent_id")
	if parentId == "" {
		parentId = "0"
	}

	// TODO: check the user permission

	ctx.SetUserValue("edit_menu_param", &MenuEditParam{
		Id:       ctx.FormValue("id"),
		Title:    ctx.FormValue("title"),
		ParentId: parentId,
		Icon:     ctx.FormValue("icon"),
		Uri:      ctx.FormValue("uri"),
		Roles:    ctx.Request.Form["roles[]"],
		Alert:    checkEmpty(ctx, "id", "title", "icon", "uri"),
	})
	ctx.Next()
	return
}

func GetMenuEditParam(ctx *context.Context) *MenuEditParam {
	return ctx.UserValue["edit_menu_param"].(*MenuEditParam)
}

func checkEmpty(ctx *context.Context, key ...string) template.HTML {
	for _, k := range key {
		if ctx.FormValue(k) == "" {
			return getAlert("wrong " + k)
		}
	}
	return template.HTML("")
}