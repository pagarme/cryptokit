package soft

type Database interface {
	ListKeys() ([]string, error)
	FindKey(id string) (map[string]interface{}, bool, error)
	Save(id string, data map[string]interface{}) error
	Remove(id string) error

	Close() error
}
