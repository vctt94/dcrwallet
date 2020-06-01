package vsp

type FeeAddressRequest struct {
	Timestamp  int64  `json:"timestamp" binding:"required"`
	TicketHash string `json:"tickethash" binding:"required"`
	TicketHex  string `json:"tickethex" binding:"required"`
}

type feeAddressResponse struct {
	Timestamp  int64             `json:"timestamp" binding:"required"`
	FeeAddress string            `json:"feeaddress" binding:"required"`
	FeeAmount  int64             `json:"feeamount" binding:"required"`
	Expiration int64             `json:"expiration" binding:"required"`
	Request    FeeAddressRequest `json:"request" binding:"required"`
}

type PayFeeRequest struct {
	Timestamp   int64             `json:"timestamp" binding:"required"`
	TicketHash  string            `json:"tickethash" binding:"required"`
	FeeTx       string            `json:"feetx" binding:"required"`
	VotingKey   string            `json:"votingkey" binding:"required"`
	VoteChoices map[string]string `json:"votechoices" binding:"required"`
}

type TicketStatusRequest struct {
	Timestamp  int64  `json:"timestamp" binding:"required"`
	TicketHash string `json:"tickethash" binding:"required"`
}

type vspInfoResponse struct {
	Timestamp     int64   `json:"timestamp" binding:"required"`
	PubKey        []byte  `json:"pubkey" binding:"required"`
	FeePercentage float64 `json:"feepercentage" binding:"required"`
	VspClosed     bool    `json:"vspclosed" binding:"required"`
	Network       string  `json:"network" binding:"required"`
}
