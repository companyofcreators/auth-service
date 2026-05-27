package kafka

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/segmentio/kafka-go"
)

type Producer struct {
	writer *kafka.Writer
	logger *slog.Logger
}

type Event struct {
	Type         string    `json:"type"`
	UserID       string    `json:"user_id"`
	Email        string    `json:"email,omitempty"`
	Name         string    `json:"name,omitempty"`
	FirstName    string    `json:"first_name,omitempty"`
	LastName     string    `json:"last_name,omitempty"`
	Phone        string    `json:"phone,omitempty"`
	VerifyToken  string    `json:"verify_token,omitempty"`
	Roles        []string  `json:"roles,omitempty"`
	Timestamp    time.Time `json:"timestamp"`
}

func NewProducer(brokers []string, logger *slog.Logger) *Producer {
	writer := &kafka.Writer{
		Addr:         kafka.TCP(brokers...),
		Balancer:     &kafka.LeastBytes{},
		RequiredAcks: kafka.RequireAll,
		WriteTimeout: 10 * time.Second,
		ReadTimeout:  5 * time.Second,
	}

	return &Producer{
		writer: writer,
		logger: logger,
	}
}

func (p *Producer) Publish(topic string, event Event) error {
	event.Timestamp = time.Now()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("failed to marshal event: %w", err)
	}

	msg := kafka.Message{
		Topic: topic,
		Key:   []byte(event.UserID),
		Value: data,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := p.writer.WriteMessages(ctx, msg); err != nil {
		p.logger.Error("failed to publish kafka event", "topic", topic, "error", err)
		return fmt.Errorf("failed to publish kafka event: %w", err)
	}

	p.logger.Debug("kafka event published", "topic", topic, "user_id", event.UserID)
	return nil
}

func (p *Producer) PublishUserCreated(userID, email, firstName, lastName, phone string, roles []string) error {
	return p.Publish("user.created", Event{
		Type:      "user.created",
		UserID:    userID,
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Phone:     phone,
		Roles:     roles,
	})
}

func (p *Producer) PublishAuthLogin(userID, email string, roles []string) error {
	return p.Publish("auth.login", Event{
		Type:   "auth.login",
		UserID: userID,
		Email:  email,
		Roles:  roles,
	})
}

func (p *Producer) PublishAuthLogout(userID string) error {
	return p.Publish("auth.logout", Event{
		Type:   "auth.logout",
		UserID: userID,
	})
}

func (p *Producer) PublishVerificationCreated(userID, email, name, verifyToken string) error {
	return p.Publish("user.verification.created", Event{
		Type:        "user.verification.created",
		UserID:      userID,
		Email:       email,
		Name:        name,
		VerifyToken: verifyToken,
	})
}

func (p *Producer) Close() error {
	return p.writer.Close()
}
