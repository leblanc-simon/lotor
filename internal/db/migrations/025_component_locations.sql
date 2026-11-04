-- 025_component_locations : emplacements des composants (ADR 0057).
--
-- Chaque élément d'un ensemble d'inventaire garde les emplacements où l'analyse a trouvé
-- son composant (sbom.Location : chemin réel, chemin d'accès, couche, preuve secondaire),
-- principaux d'abord, 32 au plus. Ils dépendent de ce qui a été analysé, pas du composant :
-- ils vont sur l'élément, et l'empreinte d'inventaire les compte. Les ensembles antérieurs
-- n'en ont pas (NULL) ; les emplacements apparaissent au scan suivant.
ALTER TABLE component_set_items
    ADD COLUMN locations jsonb CHECK (jsonb_typeof(locations) = 'array' AND jsonb_array_length(locations) BETWEEN 1 AND 32);
