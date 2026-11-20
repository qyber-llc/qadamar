# Qadamar Petra films

Three English films: `models`, `sectors`, `usecases`. Each folder contains the editable SVG scene source, script, narration clips, MP4, poster, scene timings and English captions.

Petra is the Higgsfield `seed_audio` preset `0c63637d-2ecb-5bda-9bbe-38894aa9a876`. All six brand-bearing intro/outro clips were regenerated for Qadamar. Other Petra clips were retained. Provenance is recorded in `narration-provenance.json`.

Rebuild on macOS with ffmpeg/ffprobe installed:

```sh
npm ci --prefix docs/media/renderer
node docs/media/build-vectors.mjs docs/media/models
node docs/media/build-vectors.mjs docs/media/sectors
node docs/media/build-vectors.mjs docs/media/usecases
```

The renderer uses macOS Helvetica Neue and Menlo fonts. Source scenes, narration, captions and posters share a single derived timeline. It never requires browser automation. Review `docs/DELIVERY.md` for distribution and verification limits.
