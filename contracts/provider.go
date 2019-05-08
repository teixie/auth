package contracts

type Provider interface {
	GetId() int64

	RetrieveById(int64) interface{}
}
