(ns build
  "Build script for stroopwafel

   Usage:
     clojure -T:build jar      ; Create JAR
     clojure -T:build install  ; Install to local Maven repo (~/.m2/repository)
     clojure -T:build deploy   ; Build JAR and deploy to Clojars
     clojure -T:build clean    ; Clean build artifacts"
  (:require [clojure.tools.build.api :as b]
            [deps-deploy.deps-deploy :as dd]))

(def lib 'com.github.franks42/stroopwafel)
(def version "0.11.0")
(def class-dir "target/classes")
(def jar-file (format "target/%s-%s.jar" (name lib) version))
(def basis (delay (b/create-basis {:project "deps.edn" :root nil})))

(defn clean [_]
  (println "Cleaning target directory...")
  (b/delete {:path "target"})
  (println "Done."))

(defn jar [_]
  (clean nil)
  (println (format "Building %s version %s..." lib version))
  (println (format "JAR file: %s" jar-file))

  ;; Copy source files to class-dir
  (b/copy-dir {:src-dirs ["src"]
               :target-dir class-dir})

  ;; Write pom.xml
  (b/write-pom {:class-dir class-dir
                :lib lib
                :version version
                :basis @basis
                :src-dirs ["src"]
                :pom-data [[:description "Pure Datalog engine for authorization decisions — zero external dependencies. See signet (crypto) and stroopwafel-pdp (bridge) for the full stack."]
                           [:url "https://github.com/franks42/stroopwafel"]
                           [:licenses
                            [:license
                             [:name "EPL-2.0"]
                             [:url "https://www.eclipse.org/legal/epl-2.0/"]]]
                           [:scm
                            [:url "https://github.com/franks42/stroopwafel"]
                            [:connection "scm:git:https://github.com/franks42/stroopwafel.git"]
                            [:developerConnection "scm:git:ssh://git@github.com/franks42/stroopwafel.git"]
                            [:tag (str "v" version)]]]})

  ;; Create JAR
  (b/jar {:class-dir class-dir
          :jar-file jar-file})

  (println (format "Created: %s" jar-file)))

(defn install [_]
  (jar nil)
  (println (format "Installing %s to local Maven repository..." lib))
  (b/install {:basis @basis
              :lib lib
              :version version
              :jar-file jar-file
              :class-dir class-dir})
  (println (format "Installed %s/%s to ~/.m2/repository" lib version))
  (println)
  (println "To use in deps.edn:")
  (println (format "  %s {:mvn/version \"%s\"}" lib version)))

(defn deploy [_]
  (jar nil)
  (dd/deploy {:installer :remote
              :artifact (b/resolve-path jar-file)
              :pom-file (b/pom-path {:lib lib :class-dir class-dir})}))
