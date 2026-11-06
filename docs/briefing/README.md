# Briefing pack

| Audience | Start here |
|---|---|
| **Leaders** | [Leadership brief](leadership-brief.md) |
| **Decision makers** | [Options brief](options-decision-brief.md): trade-offs, schematics and SWOTs |
| **Engineers** | [Peer technical brief](peer-technical-brief.md) |
| **Live briefing** | [Slide deck](gitlab-runner-ai-access-briefing.pptx): main deck for everyone, appendix for engineers, speaker notes on every slide |

## Diagrams

`diagrams/` has the editable `.excalidraw` files, and `diagrams/png/` has images for slides. Use **Open** at excalidraw.com or a self-hosted Excalidraw to edit them. Re-export a PNG after editing, because PNGs don't update on their own.

| File | Shows |
|---|---|
| `01-solution-overview` | Today vs proposed, in plain language |
| `02-reference-architecture` | All components, trust zones and flows |
| `03-token-exchange-sequence` | Step-by-step token exchange and API call |
| `04-option-1-instance-runner` | Option 1 schematic |
| `05-option-2-group-runners` | Option 2 schematic |
| `06-option-3-central-template` | Option 3 schematic |
| `07-runner-and-image-hardening` | Pod, network, image contents and supply chain |
| `08-sts-and-gateway-controls` | STS decisions and gateway request handling |
| `09-rollout-and-gates` | Phases, gates and blast radius |
| `10-swot-overall` | SWOT of the overall approach |
| `11` to `13` | SWOT of each access option |

The [design](../superpowers/specs/2026-11-05-gitlab-runner-ai-access-design.md) is the authority if anything here differs.
