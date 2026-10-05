// irongate-gui: janela do Iron Gate (Wails). Toda a lógica está em internal/app; aqui só há a ponte para a tela.
package main

import (
	"embed"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
)

//go:embed all:frontend
var assets embed.FS

func main() {
	a := NewApp()
	err := wails.Run(&options.App{
		Title:            "Iron Gate",
		Width:            420,
		Height:           760,
		MinWidth:         380,
		MinHeight:        640,
		AssetServer:      &assetserver.Options{Assets: assets},
		BackgroundColour: &options.RGBA{R: 24, G: 26, B: 31, A: 1},
		OnStartup:        a.startup,
		Bind:             []any{a},
	})
	if err != nil {
		log.Fatal(err)
	}
}
