package gobot

import (
	"context"
	"fmt"
	"log"

	"github.com/bwmarrin/discordgo"
	asrmod "github.com/h0tak88r/AutoAR/internal/modules/asr"
)

func handleASRBotCommand(s *discordgo.Session, i *discordgo.InteractionCreate) {
	options := i.ApplicationCommandData().Options
	var domain string
	mode := 5
	threads := 50

	for _, opt := range options {
		switch opt.Name {
		case "domain":
			domain = opt.StringValue()
		case "mode":
			mode = int(opt.IntValue())
		case "threads":
			threads = int(opt.IntValue())
		}
	}

	// Immediate response to Discord
	s.InteractionRespond(i.Interaction, &discordgo.InteractionResponse{
		Type: discordgo.InteractionResponseChannelMessageWithSource,
		Data: &discordgo.InteractionResponseData{
			Content: fmt.Sprintf("🚀 Starting ASR Mode %d scan for **%s** with %d threads...", mode, domain, threads),
		},
	})

	// Run in background
	go func() {
		opts := asrmod.Options{
			Domain:  domain,
			Mode:    mode,
			Threads: threads,
		}
		err := asrmod.Run(context.Background(), opts)
		if err != nil {
			log.Printf("[ERROR] ASR scan failed: %v", err)
			s.ChannelMessageSend(i.ChannelID, fmt.Sprintf("❌ ASR Scan for **%s** failed: %v", domain, err))
		} else {
			s.ChannelMessageSend(i.ChannelID, fmt.Sprintf("✅ ASR Scan for **%s** (Mode %d) completed successfully!", domain, mode))
		}
	}()
}
