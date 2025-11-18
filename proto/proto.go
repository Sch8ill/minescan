package proto

import "fmt"

// Proto represents an application protocol.
type Proto int

const (
	Minecraft Proto = iota
	Http

	minecraftName = "mc"
	httpName      = "http"
)

func ParseProto(proto string) (Proto, error) {
	switch proto {
	case minecraftName:
		return Minecraft, nil
	case httpName:
		return Http, nil

	default:
		return 0, fmt.Errorf("invalid protocol: %s", proto)
	}
}

func (p Proto) String() string {
	switch p {
	case Minecraft:
		return minecraftName

	case Http:
		return httpName
	}

	return "none"
}
