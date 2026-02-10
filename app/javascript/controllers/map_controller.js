import { Controller } from "@hotwired/stimulus"
import L from "leaflet"

// Stimulus controller for rendering Leaflet maps with GeoJSON markers.
//
// Usage:
//   <div data-controller="map"
//        data-map-geojson-value='{"type":"FeatureCollection","features":[...]}'
//        data-map-center-value="[39.8283,-98.5795]"
//        data-map-zoom-value="4">
//   </div>
export default class extends Controller {
  static values = {
    geojson: { type: Object, default: { type: "FeatureCollection", features: [] } },
    center: { type: Array, default: [39.8283, -98.5795] },
    zoom: { type: Number, default: 4 }
  }

  connect() {
    this.map = L.map(this.element, {
      scrollWheelZoom: false
    }).setView(this.centerValue, this.zoomValue)

    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
      maxZoom: 19
    }).addTo(this.map)

    this.renderMarkers()
  }

  disconnect() {
    if (this.map) {
      this.map.remove()
      this.map = null
    }
  }

  renderMarkers() {
    const geojson = this.geojsonValue
    if (!geojson.features || geojson.features.length === 0) return

    const geojsonLayer = L.geoJSON(geojson, {
      pointToLayer: (_feature, latlng) => {
        return L.circleMarker(latlng, {
          radius: 8,
          fillColor: "#3b82f6",
          color: "#1e40af",
          weight: 2,
          opacity: 1,
          fillOpacity: 0.7
        })
      },
      onEachFeature: (feature, layer) => {
        if (feature.properties && feature.properties.popup) {
          layer.bindPopup(feature.properties.popup)
        }
      }
    }).addTo(this.map)

    if (geojson.features.length > 1) {
      this.map.fitBounds(geojsonLayer.getBounds().pad(0.1))
    }
  }
}
