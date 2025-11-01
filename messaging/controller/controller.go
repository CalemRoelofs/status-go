package controller

import (
	"context"
	"crypto/ecdsa"
	"sync"
	"time"

	"go.uber.org/zap"

	gocommon "github.com/status-im/status-go/common"
	"github.com/status-im/status-go/crypto"
	"github.com/status-im/status-go/messaging/adapters"
	"github.com/status-im/status-go/messaging/common"
	"github.com/status-im/status-go/messaging/controller/processor"
	"github.com/status-im/status-go/messaging/controller/sender"
	"github.com/status-im/status-go/messaging/events"
	"github.com/status-im/status-go/messaging/types"
	"github.com/status-im/status-go/pkg/pubsub"
)

type Controller struct {
	identity    *ecdsa.PrivateKey
	persistence types.MessageSenderPersistence
	stack       *common.MessagingStack
	sender      *sender.Sender
	processor   *processor.Processor

	publisher *pubsub.Publisher
	logger    *zap.Logger

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewController(
	identity *ecdsa.PrivateKey,
	persistence types.MessageSenderPersistence,
	stack *common.MessagingStack,
	publisher *pubsub.Publisher,
	logger *zap.Logger,
) *Controller {
	return &Controller{
		identity:    identity,
		persistence: persistence,
		stack:       stack,
		sender:      sender.NewSender(identity, stack, logger),
		processor:   processor.NewProcessor(identity, persistence, stack, logger),
		publisher:   publisher,
		logger:      logger.Named("controller"),
		quit:        make(chan struct{}),
	}
}

func (c *Controller) Start() error {
	subscriptions, err := c.stack.Encryption.Start(c.identity)
	if err != nil {
		return err
	}

	// process stored shared secrets
	err = c.processor.ProcessSharedSecrets(subscriptions.SharedSecrets)
	if err != nil {
		return err
	}

	err = c.StartReliability()
	if err != nil {
		return err
	}

	c.runSubscriptionsLoop()
	c.runSegmentsCleanupLoop()
	c.runHashRatchetCleanupLoop()

	return nil
}

func (c *Controller) Stop() error {
	close(c.quit)

	c.StopReliability()

	err := c.stack.Encryption.Stop()
	if err != nil {
		return err
	}

	err = c.stack.Transport.Stop()
	if err != nil {
		return err
	}

	c.wg.Wait()

	return nil
}

func (c *Controller) StartReliability() error {
	return c.stack.Reliability.Start(c.sender.SendPrivateReliability)
}

func (c *Controller) StopReliability() {
	c.stack.Reliability.Stop()
}

func (c *Controller) SaveHashRatchetMessage(groupID []byte, keyID []byte, m *types.ReceivedMessage) error {
	return c.persistence.SaveHashRatchetMessage(groupID, keyID, m)
}

func (c *Controller) Sender() *sender.Sender {
	return c.sender
}

func (c *Controller) Processor() *processor.Processor {
	return c.processor
}

func (c *Controller) runSubscriptionsLoop() {
	go func() {
		defer gocommon.LogOnPanic()

		c.wg.Add(1)
		defer c.wg.Done()

		scheduledSendSub, scheduledSendUnsub := pubsub.Subscribe[sender.ScheduledReliableSend](c.sender.Publisher(), 100)
		defer scheduledSendUnsub()

		sentSub, sentUnsub := pubsub.Subscribe[sender.SentMessage](c.sender.Publisher(), 100)
		defer sentUnsub()

		deviceNotFoundSub, deviceNotFoundUnsub := pubsub.Subscribe[processor.DeviceNotFound](c.processor.Publisher(), 100)
		defer deviceNotFoundUnsub()

		for {
			select {
			case scheduledSend := <-scheduledSendSub:
				// We don't need to receive confirmations from our own devices
				if !crypto.IsPubKeyEqual(scheduledSend.Recipient, &c.identity.PublicKey) {
					confirmation := &types.RawMessageConfirmation{
						PublicKey:  crypto.CompressPubkey(scheduledSend.Recipient),
						MessageID:  scheduledSend.MessageID,
						DataSyncID: scheduledSend.ReliabilityMessageID,
					}

					err := c.persistence.InsertPendingConfirmation(confirmation)
					if err != nil {
						c.logger.Error("failed to insert pending confirmation", zap.Error(err))
					}
				}

			case messageSent := <-sentSub:
				var pubkey *ecdsa.PublicKey
				if messageSent.Private {
					pubkey = messageSent.Recipient
				}
				pubsub.Publish(c.publisher, &events.SentMessage{
					PublicKey:     pubkey,
					Installations: adapters.FromEncryptionInstallations(messageSent.RecipientInstallations),
					MessageIDs:    messageSent.MessageIDs,
				})

			case deviceNotFound := <-deviceNotFoundSub:
				err := c.sender.SendPrivateAdvertiseBundle(context.Background(), deviceNotFound.PublicKey)
				if err != nil {
					c.logger.Error("failed to handle ErrDeviceNotFound", zap.Error(err))
				}

			case <-c.quit:
				return
			}
		}
	}()
}

func (c *Controller) cleanupLoop(name string, cleanupFunc func() error) {
	logger := c.logger.Named(name)

	go func() {
		defer gocommon.LogOnPanic()

		c.wg.Add(1)
		defer c.wg.Done()

		// Delay by a few minutes to minimize messenger's startup time
		var interval time.Duration = 5 * time.Minute
		for {
			select {
			case <-time.After(interval):
				// Set the regular interval after the first execution
				interval = 1 * time.Hour

				err := cleanupFunc()
				if err != nil {
					logger.Error("failed to cleanup", zap.Error(err))
				}

			case <-c.quit:
				return
			}
		}
	}()
}

func (c *Controller) runSegmentsCleanupLoop() {
	c.cleanupLoop("segmentsCleanupLoop", func() error {
		monthAgo := time.Now().AddDate(0, -1, 0)
		return c.stack.Segmentation.CleanupStaleSegments(monthAgo)
	})
}

func (c *Controller) runHashRatchetCleanupLoop() {
	c.cleanupLoop("hashRatchetCleanupLoop", func() error {
		monthAgo := time.Now().AddDate(0, -1, 0).Unix()
		return c.persistence.DeleteHashRatchetMessagesOlderThan(monthAgo)
	})
}
